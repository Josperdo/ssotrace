package diagnose

import (
	"fmt"

	"github.com/Josperdo/ssotrace/internal/flow"
)

// destinationMismatch is SAML003: the Response says it is for one URL, but
// the browser delivered it to another. SPs must reject a signed Response
// whose Destination is not the URL it arrived at.
type destinationMismatch struct{}

func (destinationMismatch) ID() string { return "SAML003" }

func (destinationMismatch) Check(ctx Context) []Finding {
	var out []Finding
	checked := 0
	for _, v := range samlResponses(ctx) {
		// Destination is only meaningful for POST delivery, and is optional
		// in the spec when the Response is unsigned.
		if v.Msg.Binding != flow.BindingPOST || v.Resp.Destination == "" {
			continue
		}
		checked++
		if sameURL(v.Resp.Destination, v.Msg.URL) {
			continue
		}
		out = append(out, Finding{
			RuleID:   "SAML003",
			Severity: Fail,
			Title:    "Response Destination does not match where it was sent",
			Detail: "The IdP addressed the Response to one URL (Destination), but the browser posted it to another. " +
				urlMismatchHint(v.Resp.Destination, v.Msg.URL),
			Fix: "In the IdP's settings for this application, set the Assertion Consumer Service (ACS) or Reply URL to exactly " +
				"the URL the browser posted to, shown below. If the SP sits behind a proxy, make sure it knows its public URL.",
			Evidence: []Evidence{
				{Label: "Response", Value: where(v.Msg)},
				{Label: "Destination in Response", Value: v.Resp.Destination},
				{Label: "URL the browser posted to", Value: v.Msg.URL},
			},
		})
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("SAML003", "Response Destination matches where it was sent",
			fmt.Sprintf("Checked %s.", plural(checked, "SAML response")))}
	}
	return out
}
