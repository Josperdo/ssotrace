package diagnose

import (
	"fmt"
	"regexp"

	"github.com/Josperdo/ssotrace/internal/flow"
	"github.com/Josperdo/ssotrace/internal/har"
)

// redirectURIMismatch is OIDC003: the IdP rejected the redirect_uri, or
// the token request sent a different redirect_uri than the authorization
// request did (RFC 6749 §4.1.3 requires them to be identical).
//
// IdPs must not redirect to a redirect_uri they do not trust (RFC 6749
// §4.1.2.1), so a rejected redirect_uri never reaches the callback. It
// shows up as the IdP's own error page, which this rule reads.
type redirectURIMismatch struct{}

func (redirectURIMismatch) ID() string { return "OIDC003" }

// redirectURIError matches how IdPs word a rejected redirect_uri:
// Keycloak "Invalid parameter: redirect_uri" (authorization) and
// "Incorrect redirect_uri" (token request), Google
// "redirect_uri_mismatch", Okta "The 'redirect_uri' parameter must be a
// Login redirect URI", and Microsoft Entra ID's AADSTS50011. [^<>] keeps a
// match inside one piece of text rather than across HTML tags.
var redirectURIError = regexp.MustCompile(`(?i)redirect_uri_mismatch|\bAADSTS50011\b|(invalid|incorrect)[^<>]{0,20}redirect[_ ]?ur[il]|redirect[_ ]?ur[il][^<>]{0,60}(mismatch|not registered|not allowed|not valid|does not match|must be)`)

func (redirectURIMismatch) Check(ctx Context) []Finding {
	flows := oidcFlows(ctx)
	var out []Finding
	checked := 0
	for i := range flows {
		f := &flows[i]
		if f.Authorization == nil {
			continue
		}
		if where, ok := rejectedRedirectURI(ctx, f); ok {
			out = append(out, Finding{
				RuleID: "OIDC003", OIDCFlow: flowRef(i), Severity: Fail,
				Title:  "IdP rejected the redirect_uri",
				Detail: "The IdP does not have this redirect_uri registered for the client, so it refused to send the user back to the application.",
				Fix: "Add the redirect_uri from the evidence to the client's allowed redirect URIs in the IdP, exactly as shown " +
					"(Keycloak: \"Valid redirect URIs\"; Microsoft Entra ID: Authentication > Redirect URIs; Okta: \"Sign-in redirect URIs\"). " +
					"IdPs compare the whole string: http vs https, the port, a trailing slash, and letter case all count.",
				Evidence: []Evidence{
					{Label: "Authorization request", Value: sentWhere(f.Authorization.Sent)},
					{Label: "redirect_uri sent", Value: f.Authorization.Params.RedirectURI},
					{Label: "client_id", Value: f.Authorization.Params.ClientID},
					{Label: "Rejection found in", Value: where},
				},
			})
			continue
		}

		authURI := f.Authorization.Params.RedirectURI
		if f.Token == nil || authURI == "" {
			if f.Callback != nil {
				checked++ // the IdP accepted the redirect_uri: it sent the user back
			}
			continue
		}
		checked++
		tokURI := f.Token.Request.RedirectURI
		if tokURI == authURI {
			continue
		}
		fix := "Send exactly the same redirect_uri in the token request as in the authorization request; most libraries take both from one setting."
		if tokURI == "" {
			fix = "Include the redirect_uri in the token request. It is required whenever the authorization request sent one."
		} else if hint := urlMismatchHint(authURI, tokURI); hint != "" {
			fix = hint + " " + fix
		}
		ev := []Evidence{
			{Label: "Authorization request", Value: sentWhere(f.Authorization.Sent)},
			{Label: "redirect_uri sent", Value: authURI},
			{Label: "Token request", Value: sentWhere(f.Token.Sent)},
			{Label: "redirect_uri in token request", Value: orNone(tokURI)},
		}
		if r := f.Token.Response; r != nil && redirectURIError.MatchString(r.ErrorDescription) {
			ev = append(ev, Evidence{Label: "IdP said", Value: truncate(r.ErrorDescription, 300)})
		}
		out = append(out, Finding{
			RuleID: "OIDC003", OIDCFlow: flowRef(i), Severity: Fail,
			Title:    "redirect_uri differs between authorization and token requests",
			Detail:   "The token request must repeat the authorization request's redirect_uri exactly. The IdP will refuse the code (usually with invalid_grant).",
			Fix:      fix,
			Evidence: ev,
		})
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("OIDC003", "redirect_uri accepted",
			fmt.Sprintf("Checked %s.", plural(checked, "authorization request")))}
	}
	return out
}

// rejectedRedirectURI looks for the IdP saying, at the authorization step,
// that the redirect_uri is not registered: on the authorization endpoint's
// own response, or in an error callback. A token endpoint complaint about
// redirect_uri means something else (the two requests disagree), which the
// comparison in Check reports more precisely.
func rejectedRedirectURI(ctx Context, f *flow.OIDCFlow) (string, bool) {
	if ctx.HAR != nil {
		i := f.Authorization.Entry
		if i >= 0 && i < len(ctx.HAR.Log.Entries) {
			if redirectURIError.MatchString(scannableBody(&ctx.HAR.Log.Entries[i].Response.Content)) {
				return fmt.Sprintf("entry %d response body", i), true
			}
		}
	}
	if cb := f.Callback; cb != nil && redirectURIError.MatchString(cb.Params.ErrorDescription) {
		return "callback error_description", true
	}
	return "", false
}

// MentionsRedirectURIError reports whether s is an IdP's way of saying a
// redirect_uri was wrong. The redactor uses it to keep that fact when it
// removes the IdP's free text.
func MentionsRedirectURIError(s string) bool { return redirectURIError.MatchString(s) }

// RedirectURIErrorInBody applies the same check to a response body, exactly
// as OIDC003 reads it.
func RedirectURIErrorInBody(c *har.Content) bool {
	return redirectURIError.MatchString(scannableBody(c))
}
