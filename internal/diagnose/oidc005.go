package diagnose

import (
	"fmt"
	"slices"
	"strings"
)

// audienceNotClient is OIDC005: the ID token is not addressed to the
// client that receives it. The client must reject an ID token whose aud
// does not contain its client_id, or whose azp names another client (OIDC
// Core §3.1.3.7, steps 3 to 5); otherwise a token issued to one app could
// sign the user into another.
type audienceNotClient struct{}

func (audienceNotClient) ID() string { return "OIDC005" }

func (audienceNotClient) Check(ctx Context) []Finding {
	var out []Finding
	checked := 0
	for _, v := range idTokens(ctx) {
		c := v.Token.Claims
		id, source := clientID(v.Flow)
		aud := strings.Join(c.Audience, ", ")
		if aud == "" {
			aud = "(none)"
		}
		if id == "" {
			out = append(out, Finding{
				RuleID: "OIDC005", OIDCFlow: v.flowRef(), Severity: Info,
				Title:  "ID token audience could not be checked",
				Detail: "The capture does not show which client_id this sign-in used, so ssotrace cannot check the token's audience.",
				Fix:    "Capture again from the start of the sign-in, or compare the audience in the evidence with the application's client ID by hand.",
				Evidence: []Evidence{
					{Label: v.label(), Value: sentWhere(v.Sent)},
					{Label: "aud", Value: aud},
				},
			})
			continue
		}
		checked++
		ev := []Evidence{
			{Label: v.label(), Value: sentWhere(v.Sent)},
			{Label: "aud", Value: aud},
			{Label: "client_id", Value: id},
			{Label: "client_id from", Value: source},
		}
		switch {
		case !slices.Contains(c.Audience, id):
			out = append(out, Finding{
				RuleID: "OIDC005", OIDCFlow: v.flowRef(), Severity: Fail,
				Title:  "ID token audience does not include the client",
				Detail: "The ID token is addressed to a different client than the one that requested it, so the application will reject it.",
				Fix: "The application and the IdP disagree about the client ID. Check that the application is configured with the client ID " +
					"of the IdP client that issues its tokens (the same app registration, tenant, and environment), and that nothing swaps in a token from another application.",
				Evidence: ev,
			})
		case c.AZP != "" && c.AZP != id:
			out = append(out, Finding{
				RuleID: "OIDC005", OIDCFlow: v.flowRef(), Severity: Fail,
				Title:    "ID token was issued to a different client (azp)",
				Detail:   "The token's authorized party (azp) names another client. The application will reject a token that was issued to someone else.",
				Fix:      "Find which application the azp in the evidence belongs to; the token was obtained by that client, not this one.",
				Evidence: append(ev, Evidence{Label: "azp", Value: c.AZP}),
			})
		}
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("OIDC005", "ID token audience matches the client",
			fmt.Sprintf("Checked %s.", plural(checked, "ID token")))}
	}
	return out
}
