package flow

import (
	"net/url"

	"github.com/Josperdo/ssotrace/internal/har"
	"github.com/Josperdo/ssotrace/internal/oidc"
)

// Sent records where and when the browser sent an OAuth/OIDC message.
type Sent struct {
	Entry      int    `json:"entry"`            // index into log.entries
	Time       string `json:"time"`             // the entry's startedDateTime, as recorded
	Method     string `json:"method,omitempty"` // empty for a fragment callback: no request carried it
	URL        string `json:"url"`              // scheme://host/path; query and fragment dropped
	HTTPStatus int    `json:"http_status"`      // status the receiver answered with; 0 if none
}

// Delivery is how an authorization response reached the application.
type Delivery string

// Response modes (OAuth 2.0 Multiple Response Type Encoding Practices,
// OAuth 2.0 Form Post Response Mode).
const (
	DeliveryQuery    Delivery = "query"     // redirect with parameters in the query string
	DeliveryFormPost Delivery = "form_post" // auto-submitting HTML form POST
	DeliveryFragment Delivery = "fragment"  // redirect with parameters after '#'
)

// OIDCAuthorization is an authorization request found in the capture.
type OIDCAuthorization struct {
	Sent
	Params *oidc.AuthorizationRequest `json:"params"`
}

// OIDCCallback is an authorization response found in the capture.
type OIDCCallback struct {
	Sent
	Delivery Delivery       `json:"delivery"`
	Params   *oidc.Callback `json:"params"`
}

// OIDCToken is a token endpoint call made by the browser, with the answer.
type OIDCToken struct {
	Sent
	Request  *oidc.TokenRequest  `json:"request"`
	Response *oidc.TokenResponse `json:"response,omitempty"`
	// ResponseError says why the response body could not be read. It never
	// contains body content. Empty with a nil Response means no body was
	// captured.
	ResponseError string `json:"response_error,omitempty"`
	// Origin is the page origin the browser sent with the request, and
	// AllowOrigin the IdP's Access-Control-Allow-Origin answer. Together
	// they show whether the browser let the page read the response.
	Origin      string `json:"origin,omitempty"`
	AllowOrigin string `json:"allow_origin,omitempty"`
}

// CORSBlocked reports whether the browser withheld the token response from
// the page: the IdP answered a cross-origin request without allowing the
// page's origin. Browsers record such a response (often with an empty
// body) but never hand it to the page's script, so even a 200 fails.
func (t *OIDCToken) CORSBlocked() bool {
	if t.Origin == "" || t.HTTPStatus == 0 || t.AllowOrigin == "*" || t.AllowOrigin == t.Origin {
		return false
	}
	// A same-origin request needs no permission; browsers send Origin on
	// any POST, so its presence alone does not make the call cross-origin.
	u, err := url.Parse(t.URL)
	return err == nil && u.Scheme+"://"+u.Host != t.Origin
}

// OIDCFlow is one OAuth/OIDC login attempt: the authorization request, the
// callback that answered it, and the token exchange that redeemed the code.
// Any part may be missing; which part is missing is often the diagnosis.
type OIDCFlow struct {
	Authorization *OIDCAuthorization `json:"authorization,omitempty"`
	Callback      *OIDCCallback      `json:"callback,omitempty"`
	Token         *OIDCToken         `json:"token,omitempty"`
	// StateMismatch means the callback was paired with this request by its
	// redirect_uri, but its state differs (or is missing). The application
	// will reject it as a possible CSRF attempt.
	StateMismatch bool `json:"state_mismatch,omitempty"`
	// Repeats is the index of an earlier flow whose callback this flow's
	// callback repeats: the same state and code arrived again. That is what
	// reloading the callback page, or going Back to it, does. The repeat
	// has no authorization request of its own, and that is expected.
	Repeats *int `json:"repeats,omitempty"`
}

// OIDCTrace is every OAuth/OIDC message in a capture, organized into flows.
type OIDCTrace struct {
	Flows []OIDCFlow `json:"flows"`
	// Other holds token calls that are not part of a login, such as
	// refresh_token grants.
	Other []OIDCToken `json:"other,omitempty"`
}

// TraceOIDC finds, parses, and correlates the OAuth/OIDC messages in h.
func TraceOIDC(h *har.HAR) *OIDCTrace {
	c := &oidcCorrelator{
		trace:    &OIDCTrace{Flows: []OIDCFlow{}},
		byState:  map[string]int{},
		answered: map[string]int{},
	}
	if h == nil {
		return c.trace
	}
	for i := range h.Log.Entries {
		e := &h.Log.Entries[i]
		r := &e.Request
		switch {
		case isAuthorizationRequest(r):
			c.authorization(&OIDCAuthorization{
				Sent:   sent(i, e),
				Params: oidc.ParseAuthorizationRequest(requestLookup(r, "client_id")),
			})
		case isTokenRequest(r):
			c.token(tokenCall(i, e))
		case isCallback(r) || c.expectsCallback(r):
			// One message never mixes query and form parameters. Reading
			// only from where it was delivered means a query parameter
			// cannot override a form field.
			delivery, get := DeliveryQuery, oidc.Lookup(r.QueryParam)
			if hasForm(r, "state") || hasForm(r, "code") || hasForm(r, "id_token") || hasForm(r, "error") {
				delivery, get = DeliveryFormPost, r.FormParam
			}
			c.callback(&OIDCCallback{
				Sent:     sent(i, e),
				Delivery: delivery,
				Params:   oidc.ParseCallback(get),
			})
		}
		// A redirect may carry a fragment callback in its Location header,
		// whatever the request itself was.
		if cb := c.fragmentCallback(i, e); cb != nil {
			c.callback(cb)
		}
	}
	return c.trace
}

// oidcCorrelator builds flows in capture order.
type oidcCorrelator struct {
	trace *OIDCTrace
	// byState maps a state value to the flow whose authorization request
	// sent it, while that request is unanswered.
	byState map[string]int
	// answered maps a state value to the flow whose request it answered.
	// A later callback with the same state and code is a repeat of that
	// one, not a callback to a request the capture missed.
	answered map[string]int
}

func (c *oidcCorrelator) authorization(a *OIDCAuthorization) {
	// A repeated state (a retried login) points at the newer request: that
	// is the one the authorization server answered.
	if a.Params.State != "" {
		c.byState[a.Params.State] = len(c.trace.Flows)
	}
	c.trace.Flows = append(c.trace.Flows, OIDCFlow{Authorization: a})
}

// callback pairs cb with its request. state is the intended key; when it
// matches nothing, the most recent unanswered request for the same
// redirect_uri is the request this callback answers, and the difference
// in state is itself a finding.
func (c *oidcCorrelator) callback(cb *OIDCCallback) {
	flows := c.trace.Flows
	state := cb.Params.State
	if idx, ok := c.byState[state]; ok && state != "" {
		flows[idx].Callback = cb
		delete(c.byState, state)
		c.answered[state] = idx
		return
	}
	if idx := c.unanswered(cb.URL); idx >= 0 {
		f := &flows[idx]
		f.Callback = cb
		f.StateMismatch = state != f.Authorization.Params.State
		delete(c.byState, f.Authorization.Params.State)
		return
	}
	// Both state and code must match: a reload sends the identical URL or
	// form. A different code under the same state is something else.
	if idx, ok := c.answered[state]; ok && state != "" && flows[idx].Callback.Params.Code == cb.Params.Code {
		c.trace.Flows = append(c.trace.Flows, OIDCFlow{Callback: cb, Repeats: &idx})
		return
	}
	c.trace.Flows = append(c.trace.Flows, OIDCFlow{Callback: cb})
}

// unanswered returns the latest flow whose authorization request asked for
// delivery to callbackURL and has no callback yet, or -1.
func (c *oidcCorrelator) unanswered(callbackURL string) int {
	for i := len(c.trace.Flows) - 1; i >= 0; i-- {
		f := &c.trace.Flows[i]
		if f.Authorization != nil && f.Callback == nil && SameURL(f.Authorization.Params.RedirectURI, callbackURL) {
			return i
		}
	}
	return -1
}

// token attaches an authorization-code exchange to the flow whose callback
// delivered that code. The code is the only reliable link: matching by
// client or URL could pair the exchange with the wrong login.
func (c *oidcCorrelator) token(t *OIDCToken) {
	if t.Request.GrantType != "authorization_code" {
		c.trace.Other = append(c.trace.Other, *t)
		return
	}
	if code := t.Request.Code; code != "" {
		for i := range c.trace.Flows {
			f := &c.trace.Flows[i]
			if f.Token == nil && f.Callback != nil && f.Callback.Params.Code == code {
				f.Token = t
				return
			}
		}
	}
	// The code came from a callback the capture missed, or was redeemed a
	// second time; either way it is its own (partial) flow.
	c.trace.Flows = append(c.trace.Flows, OIDCFlow{Token: t})
}

// expectsCallback catches callbacks without a state parameter: a request
// to the redirect_uri of an unanswered authorization request that carries
// an authorization response.
func (c *oidcCorrelator) expectsCallback(r *har.Request) bool {
	if !hasParam(r, "code") && !hasParam(r, "error") && !hasParam(r, "id_token") {
		return false
	}
	return c.unanswered(stripQuery(r.URL)) >= 0
}

// fragmentCallback looks for an authorization response in the fragment of
// a redirect's Location. It counts only when it carries state or goes to
// a redirect_uri the capture asked for, so an unrelated "#error=..." in
// some app's redirect does not become a login.
func (c *oidcCorrelator) fragmentCallback(i int, e *har.Entry) *OIDCCallback {
	loc, ok := e.Response.Header("Location")
	if !ok {
		loc = e.Response.RedirectURL
	}
	if loc == "" {
		return nil
	}
	// Location may be relative; resolve it against the request URL.
	base, err := url.Parse(e.Request.URL)
	if err != nil {
		return nil
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return nil
	}
	target := base.ResolveReference(ref)
	values, err := oidc.FragmentParams(target.String())
	if err != nil {
		return nil
	}
	dest := stripQuery(target.String())
	if !values.Has("state") && c.unanswered(dest) < 0 {
		return nil
	}
	return &OIDCCallback{
		Sent: Sent{
			Entry:      i,
			Time:       e.StartedDateTime,
			URL:        dest,
			HTTPStatus: 0, // the browser never sends a fragment, so nobody answered it
		},
		Delivery: DeliveryFragment,
		Params:   oidc.ParseCallback(oidc.ValuesLookup(values)),
	}
}

func tokenCall(i int, e *har.Entry) *OIDCToken {
	t := &OIDCToken{
		Sent:    sent(i, e),
		Request: oidc.ParseTokenRequest(e.Request.FormParam),
	}
	t.Origin, _ = e.Request.Header("Origin")
	t.AllowOrigin, _ = e.Response.Header("Access-Control-Allow-Origin")
	if e.Response.Status == 0 {
		return t // the request never completed; there is no answer to read
	}
	body, err := e.Response.Content.Bytes()
	if err != nil {
		t.ResponseError = "response body could not be decoded"
		return t
	}
	if len(body) == 0 {
		return t // not captured
	}
	if t.Response, err = oidc.ParseTokenResponse(body); err != nil {
		t.ResponseError = err.Error()
	}
	return t
}

func sent(i int, e *har.Entry) Sent {
	return Sent{
		Entry:      i,
		Time:       e.StartedDateTime,
		Method:     e.Request.Method,
		URL:        stripQuery(e.Request.URL),
		HTTPStatus: e.Response.Status,
	}
}

// requestLookup reads parameters from the query string, or from the form
// body when key is only there (an authorization request sent as a POST).
func requestLookup(r *har.Request, key string) oidc.Lookup {
	if !hasQuery(r, key) && hasForm(r, key) {
		return r.FormParam
	}
	return r.QueryParam
}
