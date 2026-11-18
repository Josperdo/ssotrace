package diagnose

import (
	"fmt"
	"strings"
	"time"

	"github.com/Josperdo/ssotrace/internal/flow"
	"github.com/Josperdo/ssotrace/internal/oidc"
	"github.com/Josperdo/ssotrace/internal/secret"
)

// oidcFlows returns the capture's OAuth/OIDC flows. Rules that range over
// it report nothing for a capture without OIDC: that is HAR001's job.
func oidcFlows(ctx Context) []flow.OIDCFlow {
	if ctx.OIDC == nil {
		return nil
	}
	return ctx.OIDC.Flows
}

// sentWhere describes a message's position for evidence, in the same
// "entry 4: GET https://..." form SAML findings use. A fragment callback
// has no request of its own, so it names the redirect that carried it.
func sentWhere(s flow.Sent) string {
	if s.Method == "" {
		return fmt.Sprintf("entry %d: redirect to %s", s.Entry, s.URL)
	}
	return fmt.Sprintf("entry %d: %s %s", s.Entry, s.Method, s.URL)
}

// entryTime is when the browser sent HAR entry i. Like sentAt, it is the
// browser's clock, never the wall clock.
func entryTime(ctx Context, i int) (time.Time, bool) {
	if ctx.HAR == nil || i < 0 || i >= len(ctx.HAR.Log.Entries) {
		return time.Time{}, false
	}
	t, err := ctx.HAR.Log.Entries[i].Started()
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// tokenView is one JWT found in a flow, with what it is and where it
// arrived.
type tokenView struct {
	Index int // position in ctx.OIDC.Flows
	Flow  *flow.OIDCFlow
	Token *oidc.JWT
	Kind  string // "ID token" or "access token"
	From  string // "callback" or "token response"
	Sent  flow.Sent
}

func (v tokenView) flowRef() *int { return flowRef(v.Index) }

// label names the token in evidence: "ID token (token response)".
func (v tokenView) label() string { return v.Kind + " (" + v.From + ")" }

// idTokens returns every readable ID token in capture order: the one in a
// callback (implicit and hybrid flows) before the one from the token
// endpoint.
func idTokens(ctx Context) []tokenView {
	return tokens(ctx, false)
}

// tokens returns ID tokens and, when withAccess is set, access tokens that
// are JWTs. Access tokens are meant for an API, not the client, so only
// rules about the token's own validity look at them.
func tokens(ctx Context, withAccess bool) []tokenView {
	var out []tokenView
	flows := oidcFlows(ctx)
	for i := range flows {
		f := &flows[i]
		if cb := f.Callback; cb != nil && cb.Params.IDToken != nil {
			out = append(out, tokenView{i, f, cb.Params.IDToken, "ID token", "callback", cb.Sent})
		}
		if t := f.Token; t != nil && t.Response != nil {
			if t.Response.IDToken != nil {
				out = append(out, tokenView{i, f, t.Response.IDToken, "ID token", "token response", t.Sent})
			}
			if withAccess && t.Response.AccessToken != nil {
				out = append(out, tokenView{i, f, t.Response.AccessToken, "access token", "token response", t.Sent})
			}
		}
	}
	return out
}

// clientID is the client the flow belongs to, from the request that names
// it, and where that came from.
func clientID(f *flow.OIDCFlow) (id, source string) {
	if f.Authorization != nil && f.Authorization.Params.ClientID != "" {
		return f.Authorization.Params.ClientID, "client_id of the authorization request"
	}
	if f.Token != nil && f.Token.Request.ClientID != "" {
		return f.Token.Request.ClientID, "client_id of the token request"
	}
	return "", ""
}

// previewOrNone shows a session-binding value (state, nonce) safely, or
// says it is missing.
func previewOrNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return secret.Preview(s)
}

// oauthAdvice explains a standard OAuth/OIDC error value: what it means
// and what usually fixes it.
type oauthAdvice struct {
	meaning, fix string
}

// authorizationErrors covers errors returned to the callback (RFC 6749
// §4.1.2.1, OIDC Core §3.1.2.6).
var authorizationErrors = map[string]oauthAdvice{
	"access_denied": {
		"The user or a policy refused the sign-in: the user canceled or declined consent, or the IdP's access policy does not allow this user into this application.",
		"Check the IdP's sign-in log for this user at this time. If a policy blocked it, assign the user (or their group) to the application, or adjust the conditional-access or authentication policy.",
	},
	"invalid_request": {
		"The IdP considers the authorization request malformed: a required parameter is missing, repeated, or has a value it does not accept.",
		"Read error_description in the evidence; it usually names the parameter. Compare the request's parameters with the client's settings in the IdP.",
	},
	"unauthorized_client": {
		"This client is not allowed to use the requested flow.",
		"Enable the flow for this client in the IdP (Keycloak: \"Standard flow\" for response_type=code, \"Implicit flow\" for tokens in the response).",
	},
	"unsupported_response_type": {
		"The IdP does not allow the requested response_type for this client.",
		"Use response_type=code with PKCE, or enable the requested response type for the client in the IdP.",
	},
	"invalid_scope": {
		"A requested scope is unknown to the IdP or not allowed for this client.",
		"Remove the scope from the application's configuration, or create and assign it to the client in the IdP.",
	},
	"server_error": {
		"The IdP hit an internal error.",
		"Check the IdP's logs and status page at this time, then retry.",
	},
	"temporarily_unavailable": {
		"The IdP is overloaded or under maintenance.",
		"Retry later, and check the IdP's status page.",
	},
}

// silentErrors are the OIDC errors a prompt=none (silent) request returns
// when the user must interact. Apps are expected to fall back to an
// interactive sign-in, so on their own they are not a failure.
var silentErrors = map[string]bool{
	"login_required": true, "interaction_required": true,
	"consent_required": true, "account_selection_required": true,
}

// tokenErrors covers token endpoint errors (RFC 6749 §5.2).
var tokenErrors = map[string]oauthAdvice{
	"invalid_grant": {
		"The IdP refused the authorization code (or refresh token). The usual reasons: it expired (codes live for seconds to a minute), it was already used, the redirect_uri differs from the authorization request, or the PKCE code_verifier does not match the code_challenge.",
		"Redeem each code once and immediately. Make sure the token request sends the same redirect_uri as the authorization request and the code_verifier generated with that request. Double redemption often comes from a page that runs the callback handler twice.",
	},
	"invalid_client": {
		"Client authentication failed: the secret is wrong, or the IdP expects a client secret from a client that has none, such as a browser app.",
		"For a browser app, make it a public client in the IdP (Keycloak: turn \"Client authentication\" off) and use PKCE. For a server app, check the client secret and how it is sent.",
	},
	"unauthorized_client": {
		"This client is not allowed to use this grant type.",
		"Enable the grant for this client in the IdP (Keycloak: \"Standard flow\" for authorization codes).",
	},
	"unsupported_grant_type": {
		"The IdP does not support this grant type.",
		"Use the authorization_code grant with PKCE.",
	},
	"invalid_request": {
		"The token request is malformed or missing a parameter. A missing code_verifier, when the IdP requires PKCE, is a common case.",
		"Read error_description in the evidence; it usually names the parameter.",
	},
	"invalid_scope": {
		"A requested scope is unknown or not allowed.",
		"Remove the scope, or allow it for this client in the IdP.",
	},
}

// hasWord reports whether a space-separated OAuth list (response_type,
// scope) contains w.
func hasWord(list, w string) bool {
	for _, f := range strings.Fields(list) {
		if f == w {
			return true
		}
	}
	return false
}
