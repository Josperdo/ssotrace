package flow

import "github.com/Josperdo/ssotrace/internal/har"

// Protocol identifies which SSO protocol a HAR entry belongs to.
type Protocol int

// Protocols. OIDC covers plain OAuth 2.0 as well: the two share the
// authorization request, callback, and token request shapes detected here.
const (
	None Protocol = iota
	SAML
	OIDC
)

func (p Protocol) String() string {
	switch p {
	case None:
		return "none"
	case SAML:
		return "saml"
	case OIDC:
		return "oidc"
	default:
		return "unknown"
	}
}

// samlParams are the parameter names the SAML bindings use to carry a
// message: in the query string for HTTP-Redirect, in a form body for
// HTTP-POST, and SAMLart for the Artifact binding.
var samlParams = []string{"SAMLRequest", "SAMLResponse", "SAMLart"}

// Detect reports which SSO protocol, if any, an entry's request carries.
//
// It looks only at parameter names, never at values, so it is cheap and
// cannot be fooled into decoding anything. Deciding whether a message is
// well-formed is the parsers' job, not this function's.
func Detect(e *har.Entry) Protocol {
	r := &e.Request
	for _, name := range samlParams {
		if hasParam(r, name) {
			return SAML
		}
	}
	if isAuthorizationRequest(r) || isCallback(r) || isTokenRequest(r) {
		return OIDC
	}
	return None
}

// isAuthorizationRequest matches the browser's trip to the authorization
// endpoint. client_id and response_type are both required there (OAuth 2.0,
// RFC 6749 §4.1.1), and the pair rarely appears anywhere else.
func isAuthorizationRequest(r *har.Request) bool {
	return hasQuery(r, "client_id") && hasQuery(r, "response_type")
}

// isCallback matches the redirect back to the application, delivered in the
// query string or, with response_mode=form_post, in a POST body. Requiring
// state alongside the result keeps unrelated "code" or "error" parameters
// from matching.
func isCallback(r *har.Request) bool {
	if !hasParam(r, "state") {
		return false
	}
	return hasParam(r, "code") || hasParam(r, "id_token") || hasParam(r, "error")
}

// isTokenRequest matches a token endpoint call made by the browser, as
// single-page apps using PKCE do. grant_type is required in every token
// request (RFC 6749 §4.1.3).
func isTokenRequest(r *har.Request) bool {
	_, ok := r.FormParam("grant_type")
	return ok
}

func hasParam(r *har.Request, name string) bool {
	return hasQuery(r, name) || hasForm(r, name)
}

func hasQuery(r *har.Request, name string) bool {
	_, ok := r.QueryParam(name)
	return ok
}

func hasForm(r *har.Request, name string) bool {
	_, ok := r.FormParam(name)
	return ok
}
