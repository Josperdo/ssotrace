package diagnose

import "fmt"

// nonceMismatch is OIDC004: the ID token's nonce is not the one the
// application sent. The nonce ties an ID token to one sign-in in one
// browser; without a match, the client must reject the token as a possible
// replay (OIDC Core §3.1.3.7, step 11).
type nonceMismatch struct{}

func (nonceMismatch) ID() string { return "OIDC004" }

func (nonceMismatch) Check(ctx Context) []Finding {
	var out []Finding
	checked := 0
	for _, v := range idTokens(ctx) {
		a := v.Flow.Authorization
		if a == nil || !a.Params.HasNonce {
			continue // nothing was sent, so there is nothing to compare
		}
		checked++
		sent, got := a.Params.Nonce, v.Token.Claims.Nonce
		if got == sent {
			continue
		}
		title, detail := "ID token nonce does not match", "The ID token carries a different nonce than the one the application sent, so the application will reject it."
		if got == "" {
			title, detail = "ID token has no nonce", "The application sent a nonce, but the ID token has no nonce claim. OIDC requires the IdP to echo it, and the application will reject the token."
		}
		out = append(out, Finding{
			RuleID: "OIDC004", OIDCFlow: v.flowRef(), Severity: Fail,
			Title:  title,
			Detail: detail,
			Fix: "A missing nonce points at the IdP or a proxy dropping the parameter; check that the authorization request reaches the IdP intact. " +
				"A different nonce means the token belongs to another sign-in: two sign-ins started in parallel (tabs, double clicks), " +
				"or the application regenerated its nonce before the callback arrived. Start one sign-in at a time and keep the nonce in the session until the callback.",
			Evidence: []Evidence{
				{Label: "Authorization request", Value: sentWhere(a.Sent)},
				{Label: v.label(), Value: sentWhere(v.Sent)},
				{Label: "nonce sent", Value: previewOrNone(sent)},
				{Label: "nonce in ID token", Value: previewOrNone(got)},
			},
		})
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("OIDC004", "ID token nonce matches",
			fmt.Sprintf("Checked %s against the nonce the application sent.", plural(checked, "ID token")))}
	}
	return out
}
