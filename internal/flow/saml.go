package flow

import (
	"net/url"
	"time"

	"github.com/Josperdo/ssotrace/internal/har"
	"github.com/Josperdo/ssotrace/internal/saml"
)

// Binding is the SAML transport a message used.
type Binding string

// SAML bindings seen in browser traffic.
const (
	BindingRedirect Binding = "HTTP-Redirect" // deflated, in the query string
	BindingPOST     Binding = "HTTP-POST"     // base64, in a form body
	BindingArtifact Binding = "HTTP-Artifact" // a reference, resolved server to server
)

// SAMLMessage is one SAML message found in the capture, with where and when
// the browser actually sent it. Rules compare these facts against what the
// message claims (for example Destination against URL).
type SAMLMessage struct {
	Entry      int     `json:"entry"`       // index into log.entries
	Time       string  `json:"time"`        // the entry's startedDateTime, as recorded
	Method     string  `json:"method"`      // HTTP method the browser used
	URL        string  `json:"url"`         // scheme://host/path the browser sent it to; query dropped
	HTTPStatus int     `json:"http_status"` // status the receiver answered with; 0 if none
	Param      string  `json:"param"`       // SAMLRequest, SAMLResponse, or SAMLart
	Binding    Binding `json:"binding"`

	Message *saml.Message `json:"message,omitempty"`
	// Error says why the message could not be decoded or parsed. It never
	// contains message content.
	Error string `json:"error,omitempty"`
}

// SAMLFlow pairs an AuthnRequest with the Response that answered it.
//
// Either side may be missing: a Request with no Response means the login
// never came back to the SP; a Response with no Request is either
// IdP-initiated (no InResponseTo) or answers a request the capture missed.
type SAMLFlow struct {
	Request      *SAMLMessage `json:"request,omitempty"`
	Response     *SAMLMessage `json:"response,omitempty"`
	IDPInitiated bool         `json:"idp_initiated"`
	// UnmatchedInResponseTo means the Response names a request ID that does
	// not appear in the capture: recording started late, or the request was
	// reused or forged.
	UnmatchedInResponseTo bool `json:"unmatched_in_response_to,omitempty"`
}

// SAMLTrace is every SAML message in a capture, organized into flows.
type SAMLTrace struct {
	Flows []SAMLFlow `json:"flows"`
	// Other holds messages that are not part of a login flow (logout,
	// artifacts) or that could not be decoded.
	Other []SAMLMessage `json:"other,omitempty"`
}

// TraceSAML finds, decodes, and correlates the SAML messages in h.
func TraceSAML(h *har.HAR) *SAMLTrace {
	if h == nil {
		return &SAMLTrace{Flows: []SAMLFlow{}}
	}
	return correlate(extract(h))
}

// paramSpec says where a SAML parameter may appear and how it is encoded
// there. The binding is decided by location, not by the HTTP method: a
// Redirect is a query parameter, a POST is a form field.
type paramSpec struct {
	name    string
	inQuery bool
	binding Binding
}

var samlLocations = []paramSpec{
	{"SAMLRequest", true, BindingRedirect},
	{"SAMLResponse", true, BindingRedirect},
	{"SAMLRequest", false, BindingPOST},
	{"SAMLResponse", false, BindingPOST},
	{"SAMLart", true, BindingArtifact},
	{"SAMLart", false, BindingArtifact},
}

func extract(h *har.HAR) []SAMLMessage {
	var out []SAMLMessage
	for i := range h.Log.Entries {
		e := &h.Log.Entries[i]
		if Detect(e) != SAML {
			continue
		}
		// The HAR timestamp is the reference time for certificate
		// validity. If it is missing, the zero time makes certificate
		// checks fail rather than silently using today's date.
		at, _ := e.Started()

		for _, loc := range samlLocations {
			var value string
			var ok bool
			if loc.inQuery {
				value, ok = e.Request.QueryParam(loc.name)
			} else {
				value, ok = e.Request.FormParam(loc.name)
			}
			if !ok {
				continue
			}
			m := SAMLMessage{
				Entry:      i,
				Time:       e.StartedDateTime,
				Method:     e.Request.Method,
				URL:        stripQuery(e.Request.URL),
				HTTPStatus: e.Response.Status,
				Param:      loc.name,
				Binding:    loc.binding,
			}
			if loc.binding != BindingArtifact {
				decodeInto(&m, value, at)
			}
			out = append(out, m)
		}
	}
	return out
}

func decodeInto(m *SAMLMessage, value string, at time.Time) {
	var raw []byte
	var err error
	if m.Binding == BindingRedirect {
		raw, err = saml.DecodeRedirect(value)
	} else {
		raw, err = saml.DecodePOST(value)
	}
	if err != nil {
		m.Error = err.Error()
		return
	}
	msg, err := saml.Parse(raw, at)
	m.Message = msg
	if err != nil {
		m.Error = err.Error()
	}
}

// correlate pairs Responses to AuthnRequests by InResponseTo, keeping
// capture order.
func correlate(msgs []SAMLMessage) *SAMLTrace {
	t := &SAMLTrace{Flows: []SAMLFlow{}}
	open := map[string]int{} // AuthnRequest ID -> index in t.Flows, while unanswered

	for i := range msgs {
		m := &msgs[i]
		switch {
		case isKind(m, saml.KindAuthnRequest):
			// A repeated ID (the user clicked "log in" twice) replaces the
			// older request: the newer one is what the IdP answered.
			open[m.Message.AuthnRequest.ID] = len(t.Flows)
			t.Flows = append(t.Flows, SAMLFlow{Request: m})

		case isKind(m, saml.KindResponse):
			irt := m.Message.Response.InResponseTo
			if irt == "" {
				t.Flows = append(t.Flows, SAMLFlow{Response: m, IDPInitiated: true})
				continue
			}
			if idx, ok := open[irt]; ok {
				t.Flows[idx].Response = m
				delete(open, irt)
				continue
			}
			t.Flows = append(t.Flows, SAMLFlow{Response: m, UnmatchedInResponseTo: true})

		default:
			t.Other = append(t.Other, *m)
		}
	}
	return t
}

func isKind(m *SAMLMessage, k saml.Kind) bool {
	if m.Message == nil || m.Message.Kind != k {
		return false
	}
	switch k {
	case saml.KindAuthnRequest:
		return m.Message.AuthnRequest != nil
	case saml.KindResponse:
		return m.Message.Response != nil
	}
	return false
}

// stripQuery keeps scheme, host, and path. The query string is where
// Redirect-binding messages and OAuth codes live, so it never goes into
// the model.
func stripQuery(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + u.Path
}
