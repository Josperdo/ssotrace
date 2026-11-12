package diagnose

import (
	"fmt"
	"strconv"
)

// correlation is SAML005: does every AuthnRequest get an answer, and does
// every Response answer a request? It reports three situations:
//
//   - a request with no Response: the login stopped at the IdP;
//   - a Response naming a request ID the capture does not contain;
//   - an IdP-initiated Response (no InResponseTo), which is informational.
type correlation struct{}

func (correlation) ID() string { return "SAML005" }

func (correlation) Check(ctx Context) []Finding {
	if ctx.SAML == nil || len(ctx.SAML.Flows) == 0 {
		return nil
	}
	var out []Finding
	paired := 0
	for i := range ctx.SAML.Flows {
		f := &ctx.SAML.Flows[i]
		switch {
		case f.Request != nil && f.Response != nil:
			paired++

		case f.Request != nil:
			out = append(out, unansweredRequest(f.Request.HTTPStatus, where(f.Request)))

		case f.IDPInitiated:
			out = append(out, Finding{
				RuleID:   "SAML005",
				Severity: Info,
				Title:    "IdP-initiated login",
				Detail: "This Response does not answer an AuthnRequest: the login started at the IdP (for example from an app portal or dashboard), not at the SP. " +
					"Some SPs reject IdP-initiated logins, and ssotrace cannot check the SP's expectations (such as its entity ID) without a request to compare against.",
				Fix: "If the SP rejects it, either allow IdP-initiated SSO in the SP's settings or start the login from the application instead.",
				Evidence: []Evidence{
					{Label: "Response", Value: where(f.Response)},
				},
			})

		case f.UnmatchedInResponseTo:
			out = append(out, Finding{
				RuleID:   "SAML005",
				Severity: Warn,
				Title:    "Response answers a request that is not in the capture",
				Detail: "The Response's InResponseTo names an AuthnRequest that does not appear in this HAR. " +
					"Usually recording started after the login began. If the SP also rejects the Response, it has likely lost track of the request: " +
					"its session cookie was dropped (often a SameSite cookie problem on the cross-site POST back from the IdP), the login took longer than the SP waits, or the Response was sent twice.",
				Fix: "Capture again from the very start of the login with \"Preserve log\" on. If the SP reports an unknown or unsolicited response, " +
					"check that its session cookie survives the POST from the IdP (SameSite=None; Secure) and that the user is not using an old bookmark of the IdP page.",
				Evidence: []Evidence{
					{Label: "Response", Value: where(f.Response)},
					{Label: "InResponseTo", Value: f.Response.Message.Response.InResponseTo},
				},
			})
		}
	}
	if len(out) == 0 && paired > 0 {
		return []Finding{passFinding("SAML005", "Every request was answered",
			fmt.Sprintf("Matched %s to the AuthnRequest each one answers.", plural(paired, "SAML response")))}
	}
	return out
}

// unansweredRequest reports an AuthnRequest that never got a Response. The
// IdP's HTTP status separates "the IdP rejected the request outright" (a
// configuration problem) from "the user never finished signing in".
func unansweredRequest(status int, loc string) Finding {
	ev := []Evidence{
		{Label: "AuthnRequest", Value: loc},
		{Label: "IdP HTTP status", Value: statusText(status)},
	}
	if status >= 400 {
		return Finding{
			RuleID:   "SAML005",
			Severity: Fail,
			Title:    "IdP rejected the login request",
			Detail: "The IdP answered the SP's AuthnRequest with an HTTP error and never sent a Response back. " +
				"The request was refused before any sign-in page: the IdP did not accept something in it.",
			Fix: "Check the IdP's logs at this time. The usual causes are an ACS URL in the request that is not registered for this application " +
				"(\"invalid redirect URI\"), an SP entity ID (Issuer) the IdP does not know, or a request signature the IdP requires but could not verify.",
			Evidence: ev,
		}
	}
	return Finding{
		RuleID:   "SAML005",
		Severity: Warn,
		Title:    "Login request was never answered",
		Detail: "The SP sent an AuthnRequest, but no SAML Response came back in this capture. " +
			"Either the user stopped at the IdP's sign-in page, the IdP showed an error page, or recording stopped too early.",
		Fix: "Look at the IdP pages that follow this request in the capture for an error message. If the user did sign in, capture again " +
			"and keep recording until the application shows its error.",
		Evidence: ev,
	}
}

func statusText(status int) string {
	if status == 0 {
		return "no response recorded"
	}
	return strconv.Itoa(status)
}
