package diagnose

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Josperdo/ssotrace/internal/flow"
	"github.com/Josperdo/ssotrace/internal/saml"
)

// responseView is one decoded SAML Response together with the flow it
// belongs to, which is what most SAML rules iterate over.
type responseView struct {
	Flow *flow.SAMLFlow
	Msg  *flow.SAMLMessage
	Resp *saml.Response
}

// samlResponses returns every decoded Response in capture order. Rules that
// call it report nothing when it is empty: a capture without SAML is
// HAR001's finding, not theirs.
func samlResponses(ctx Context) []responseView {
	if ctx.SAML == nil {
		return nil
	}
	var out []responseView
	for i := range ctx.SAML.Flows {
		f := &ctx.SAML.Flows[i]
		if f.Response == nil || f.Response.Message == nil || f.Response.Message.Response == nil {
			continue
		}
		out = append(out, responseView{Flow: f, Msg: f.Response, Resp: f.Response.Message.Response})
	}
	return out
}

// request returns the AuthnRequest this view's Response answers, if the
// capture has it.
func (v responseView) request() *saml.AuthnRequest {
	if v.Flow.Request == nil || v.Flow.Request.Message == nil {
		return nil
	}
	return v.Flow.Request.Message.AuthnRequest
}

// where describes a message's position for evidence: "entry 4: POST
// https://sp.example/acs". People use it to find the request in DevTools.
func where(m *flow.SAMLMessage) string {
	return fmt.Sprintf("entry %d: %s %s", m.Entry, m.Method, m.URL)
}

// spEntityID works out which entity ID the SP uses, from evidence in the
// capture, and says how it knows. The Response itself cannot be trusted to
// say: its Audience is exactly what SAML002 needs to check.
//
// The best source is the Issuer of the AuthnRequest this Response answers.
// For a Response without one (IdP-initiated, or the request was not
// captured), any AuthnRequest in the capture that asked for delivery to the
// same ACS URL came from the same SP.
func spEntityID(ctx Context, v responseView) (id, source string) {
	if r := v.request(); r != nil && r.Issuer != "" {
		return r.Issuer, "Issuer of the AuthnRequest this Response answers"
	}
	for i := range ctx.SAML.Flows {
		req := ctx.SAML.Flows[i].Request
		if req == nil || req.Message == nil || req.Message.AuthnRequest == nil {
			continue
		}
		ar := req.Message.AuthnRequest
		if ar.Issuer != "" && ar.ACSURL != "" && sameURL(ar.ACSURL, v.Msg.URL) {
			return ar.Issuer, "Issuer of another AuthnRequest in the capture with the same ACS URL"
		}
	}
	return "", ""
}

// sameURL compares two URLs the way an SP comparing Destination or
// Recipient should: scheme and host case-insensitively, default ports
// dropped, path exactly, query ignored.
func sameURL(a, b string) bool {
	na, okA := normalizeURL(a)
	nb, okB := normalizeURL(b)
	return okA && okB && na == nb
}

func normalizeURL(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, true
}

// urlMismatchHint explains the most common reasons two URLs differ, so the
// fix line can point at the exact difference instead of "they differ".
func urlMismatchHint(claimed, actual string) string {
	c, errC := url.Parse(claimed)
	a, errA := url.Parse(actual)
	if errC != nil || errA != nil {
		return ""
	}
	switch {
	case !strings.EqualFold(c.Scheme, a.Scheme):
		return fmt.Sprintf("The scheme differs (%s vs %s). This usually means the SP sits behind a TLS-terminating proxy or load balancer and builds its URLs from the internal http address.", c.Scheme, a.Scheme)
	case !strings.EqualFold(c.Hostname(), a.Hostname()):
		return "The host differs. The IdP is configured with a different hostname than the one the user's browser actually used (an old domain, a staging host, or an internal name)."
	case c.Port() != a.Port():
		return "The port differs. A proxy or load balancer is probably changing the port between the browser and the SP."
	case strings.TrimSuffix(c.Path, "/") == strings.TrimSuffix(a.Path, "/"):
		return "Only a trailing slash differs. Many SPs compare these URLs as exact strings."
	case strings.EqualFold(c.Path, a.Path):
		return "Only the letter case of the path differs. Many SPs compare these URLs as exact strings."
	default:
		return "The path differs: the IdP has a different Assertion Consumer Service URL on file than the one the SP uses."
	}
}

func passFinding(id, title, detail string) Finding {
	return Finding{RuleID: id, Severity: Pass, Title: title, Detail: detail}
}

// plural returns "1 response" or "3 responses".
func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// lastPart returns the text after the final ':' of a SAML URN, e.g.
// "AuthnFailed" for "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed".
func lastPart(urn string) string {
	if i := strings.LastIndex(urn, ":"); i >= 0 {
		return urn[i+1:]
	}
	return urn
}
