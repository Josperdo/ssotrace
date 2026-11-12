package diagnose

import (
	"fmt"
	"slices"
	"strings"
)

// audienceMismatch is SAML002: the assertion is addressed to a different
// SP than the one receiving it. SPs must reject an assertion whose
// Audience is not their own entity ID; otherwise an assertion issued for
// one application could be replayed against another.
type audienceMismatch struct{}

func (audienceMismatch) ID() string { return "SAML002" }

func (audienceMismatch) Check(ctx Context) []Finding {
	views := samlResponses(ctx)
	var out []Finding
	checked := 0
	for _, v := range views {
		spID, source := spEntityID(ctx, v)
		for _, a := range v.Resp.Assertions {
			if a.Conditions == nil || len(a.Conditions.Audiences) == 0 {
				continue // nothing to compare; no audience restriction
			}
			auds := a.Conditions.Audiences
			if spID == "" {
				out = append(out, Finding{
					RuleID:   "SAML002",
					Flow:     v.flowRef(),
					Severity: Info,
					Title:    "Audience could not be checked",
					Detail: "The capture contains no AuthnRequest from this SP, so ssotrace cannot tell which entity ID the SP expects. " +
						"This is normal for IdP-initiated logins.",
					Fix: "To check the audience, capture an SP-initiated login (start from the application's own sign-in page), " +
						"or compare the assertion audience in the evidence with the SP's entity ID by hand.",
					Evidence: []Evidence{
						{Label: "Response", Value: where(v.Msg)},
						{Label: "Assertion audience", Value: strings.Join(auds, ", ")},
					},
				})
				continue
			}
			checked++
			if slices.Contains(auds, spID) {
				continue
			}
			f := Finding{
				RuleID:   "SAML002",
				Flow:     v.flowRef(),
				Severity: Fail,
				Title:    "Assertion audience does not match the SP",
				Detail: "The IdP addressed this assertion to a different SP (Audience) than the one that requested the login. " +
					"The SP will reject it.",
				Fix: "In the IdP's settings for this application, set the Audience (also called Entity ID, Identifier, or Audience URI) " +
					"to exactly the SP entity ID in the evidence. Watch for http vs https, trailing slashes, and an old or staging value.",
				Evidence: []Evidence{
					{Label: "Response", Value: where(v.Msg)},
					{Label: "Assertion audience", Value: strings.Join(auds, ", ")},
					{Label: "SP entity ID", Value: spID},
					{Label: "SP entity ID from", Value: source},
				},
			}
			if !a.Verified {
				f.Evidence = append(f.Evidence, Evidence{Label: "Note", Value: "this assertion's signature did not verify, so its contents may have been altered"})
			}
			out = append(out, f)
		}
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("SAML002", "Assertion audience matches the SP",
			fmt.Sprintf("Checked %s against the SP entity ID.", plural(checked, "assertion")))}
	}
	return out
}
