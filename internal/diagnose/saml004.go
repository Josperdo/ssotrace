package diagnose

import (
	"fmt"
	"strings"

	"github.com/Josperdo/ssotrace/internal/flow"
)

// bearerMethod is the SubjectConfirmation method used by browser SSO.
const bearerMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer" //nolint:gosec // public SAML spec URI, not a credential

// recipientMismatch is SAML004: the assertion's bearer confirmation names a
// different Recipient than the URL the browser delivered it to. Unlike
// Destination (on the Response envelope), Recipient is inside the signed
// assertion, so it is the check SPs rely on most.
type recipientMismatch struct{}

func (recipientMismatch) ID() string { return "SAML004" }

func (recipientMismatch) Check(ctx Context) []Finding {
	var out []Finding
	checked := 0
	for _, v := range samlResponses(ctx) {
		if v.Msg.Binding != flow.BindingPOST {
			continue
		}
		for _, a := range v.Resp.Assertions {
			var recipients []string
			for _, c := range a.Subject.Confirmations {
				if c.Method == bearerMethod && c.Recipient != "" {
					recipients = append(recipients, c.Recipient)
				}
			}
			if len(recipients) == 0 {
				continue
			}
			checked++
			// The SP accepts the assertion if any bearer confirmation fits.
			ok := false
			for _, r := range recipients {
				if sameURL(r, v.Msg.URL) {
					ok = true
					break
				}
			}
			if ok {
				continue
			}
			out = append(out, Finding{
				RuleID:   "SAML004",
				Severity: Fail,
				Title:    "Assertion Recipient does not match where it was sent",
				Detail: "The assertion may only be delivered to the URL in its Recipient, but the browser posted it somewhere else. " +
					urlMismatchHint(recipients[0], v.Msg.URL),
				Fix: "In the IdP's settings for this application, set the Assertion Consumer Service (ACS) or Reply URL to exactly " +
					"the URL the browser posted to, shown below.",
				Evidence: []Evidence{
					{Label: "Response", Value: where(v.Msg)},
					{Label: "Recipient in assertion", Value: strings.Join(recipients, ", ")},
					{Label: "URL the browser posted to", Value: v.Msg.URL},
				},
			})
		}
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("SAML004", "Assertion Recipient matches where it was sent",
			fmt.Sprintf("Checked %s.", plural(checked, "assertion")))}
	}
	return out
}
