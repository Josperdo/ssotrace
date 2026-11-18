package diagnose

import (
	"fmt"
	"strconv"

	"github.com/Josperdo/ssotrace/internal/flow"
)

// tokenEndpointError is OIDC007: a token call the browser made did not
// succeed. For an authorization code this is the last step of the sign-in
// failing; for a refresh token it ends the session early, which is a
// warning, not a failed sign-in.
type tokenEndpointError struct{}

func (tokenEndpointError) ID() string { return "OIDC007" }

func (tokenEndpointError) Check(ctx Context) []Finding {
	if ctx.OIDC == nil {
		return nil
	}
	var out []Finding
	checked := 0
	check := func(ref *int, f *flow.OIDCFlow, t *flow.OIDCToken) {
		if t.HTTPStatus == 200 && !t.CORSBlocked() {
			checked++
			return
		}
		out = append(out, tokenErrorFinding(ref, f, t, ctx.OIDC.Flows))
	}
	for i := range ctx.OIDC.Flows {
		f := &ctx.OIDC.Flows[i]
		if f.Token != nil {
			check(flowRef(i), f, f.Token)
		}
	}
	for i := range ctx.OIDC.Other {
		check(nil, nil, &ctx.OIDC.Other[i])
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("OIDC007", "Token requests succeeded",
			fmt.Sprintf("Checked %s.", plural(checked, "token request")))}
	}
	return out
}

func tokenErrorFinding(ref *int, f *flow.OIDCFlow, t *flow.OIDCToken, flows []flow.OIDCFlow) Finding {
	grant := t.Request.GrantType
	ev := []Evidence{
		{Label: "Token request", Value: sentWhere(t.Sent)},
		{Label: "grant_type", Value: truncate(grant, 64)},
	}

	if t.HTTPStatus == 0 {
		return Finding{
			RuleID: "OIDC007", OIDCFlow: ref, Severity: Warn,
			Title: "Token request never completed",
			Detail: "The browser sent the token request but recorded no response. For a browser app this is usually CORS: " +
				"the IdP did not allow the application's origin, so the browser blocked the answer. It can also be a canceled request or a network failure.",
			Fix: "Check the browser console for a CORS error. If there is one, allow the application's origin for this client in the IdP " +
				"(Keycloak: \"Web origins\"; Microsoft Entra ID: register the redirect URI as a single-page application).",
			Evidence: ev,
		}
	}

	ev = append(ev, Evidence{Label: "IdP HTTP status", Value: strconv.Itoa(t.HTTPStatus)})

	if t.CORSBlocked() {
		allowed := "none"
		if t.AllowOrigin != "" {
			allowed = truncate(t.AllowOrigin, 120)
		}
		ev = append(ev,
			Evidence{Label: "Page origin", Value: truncate(t.Origin, 120)},
			Evidence{Label: "Access-Control-Allow-Origin", Value: allowed})
		if r := t.Response; r != nil && r.Error != "" {
			ev = append(ev, Evidence{Label: "error", Value: truncate(r.Error, 64)})
		}
		sev := Fail
		if grant != "authorization_code" {
			sev = Warn
		}
		return Finding{
			RuleID: "OIDC007", OIDCFlow: ref, Severity: sev,
			Title: "Browser blocked the token response (CORS)",
			Detail: fmt.Sprintf("The IdP answered HTTP %d but did not allow the application's origin, so the browser withheld the answer "+
				"from the application. Browsers often record such a response with an empty body, which is why no error text is visible.", t.HTTPStatus),
			Fix: "Allow the application's origin for this client in the IdP " +
				"(Keycloak: \"Web origins\"; Microsoft Entra ID: register the redirect URI as a single-page application).",
			Evidence: ev,
		}
	}

	sev, title := Fail, "Token endpoint refused the authorization code"
	detail := "The browser got an authorization code but could not exchange it for tokens, so the sign-in fails at its last step."
	if grant != "authorization_code" {
		sev, title = Warn, "Token endpoint refused a "+truncate(grant, 40)+" request"
		detail = "A token request outside the sign-in itself failed. For a refresh token this usually means the session expired or was revoked, and the user has to sign in again."
	}
	fix := "Read error_description in the evidence, then check the IdP's logs at this time."

	r := t.Response
	switch {
	case r != nil && r.Error != "":
		ev = append(ev, Evidence{Label: "error", Value: truncate(r.Error, 64)})
		if r.ErrorDescription != "" {
			ev = append(ev, Evidence{Label: "error_description", Value: truncate(r.ErrorDescription, 300)})
		}
		if a, ok := tokenErrors[r.Error]; ok {
			detail += " " + a.meaning
			fix = a.fix
		}
	case t.ResponseError != "":
		ev = append(ev, Evidence{Label: "Response", Value: t.ResponseError})
		detail += " The response was not an OAuth error, which suggests something in front of the IdP (a proxy, firewall, or gateway) answered instead."
		fix = "Check proxies and gateways between the browser and the IdP's token endpoint, and the IdP's own availability."
	}

	// The most common PKCE mistake is visible in the capture: the request
	// used a code_challenge, but the token request sent no verifier.
	if f != nil && f.Authorization != nil && f.Authorization.Params.HasCodeChallenge && !t.Request.HasCodeVerifier {
		ev = append(ev, Evidence{Label: "PKCE", Value: "the authorization request sent a code_challenge, but the token request has no code_verifier"})
		fix = "Send the code_verifier generated with this sign-in's code_challenge in the token request. " + fix
	}

	// A reload or Back on the callback page re-sends the same code. When
	// the original login already redeemed it, that is the whole story, and
	// the generic list of invalid_grant causes would only mislead.
	if f != nil && f.Repeats != nil {
		n := *f.Repeats + 1
		ev = append(ev, Evidence{Label: "Repeats", Value: fmt.Sprintf("login %d's callback (same state and code)", n)})
		if *f.Repeats < len(flows) && flows[*f.Repeats].Token != nil {
			detail = fmt.Sprintf("The callback page was loaded again (a reload or the Back button), so the application "+
				"tried to redeem login %d's code a second time. Codes work once, so the IdP refused it.", n)
			fix = fmt.Sprintf("Check login %d: if its token request succeeded, the sign-in itself worked and this failure is only the reload. "+
				"To stop it recurring, have the application redeem the code once and then replace the callback URL "+
				"(a redirect, or history.replaceState in a browser app), so a reload or Back cannot send the code again.", n)
		}
	}
	return Finding{RuleID: "OIDC007", OIDCFlow: ref, Severity: sev, Title: title, Detail: detail, Fix: fix, Evidence: ev}
}
