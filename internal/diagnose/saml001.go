package diagnose

import (
	"fmt"
	"strings"
)

// statusNotSuccess is SAML001: the IdP answered with an error status
// instead of a login.
type statusNotSuccess struct{}

func (statusNotSuccess) ID() string { return "SAML001" }

const statusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

// statusHelp explains a status code in plain words, with what to do about
// it. Keys are the last part of the status URN.
type statusHelp struct{ meaning, fix string }

// topLevelStatus covers the first-level codes, which say whose fault it is.
var topLevelStatus = map[string]statusHelp{
	"Requester": {
		"The IdP says the problem is in the SP's request.",
		"Check the SP's SAML settings against what the IdP expects: entity ID, ACS URL, requested NameID format, and authentication context.",
	},
	"Responder": {
		"The IdP says the problem is on its side, or it refused to log the user in.",
		"Check the IdP's sign-in logs for this user and time; they usually name the exact reason.",
	},
	"VersionMismatch": {
		"The IdP does not support the SAML version in the request.",
		"Make sure the SP sends SAML 2.0 messages.",
	},
}

// secondLevelStatus covers the second-level codes, which say what went
// wrong. These are the ones a help desk can act on.
var secondLevelStatus = map[string]statusHelp{
	"AuthnFailed": {
		"The user could not be authenticated: a wrong password, a failed MFA prompt, or a locked or disabled account.",
		"Have the user sign in to the IdP directly to see the real error, and check the account's status and MFA registration.",
	},
	"RequestDenied": {
		"The IdP refused this login. Most often the user is not assigned to this application, or a conditional-access policy blocked it.",
		"In the IdP, check that the user (or one of their groups) is assigned to the application, and review any access policies that apply.",
	},
	"NoPassive": {
		"The SP asked for a silent login (IsPassive), but the user has no session at the IdP, so the IdP could not log them in without showing a page.",
		"This is normal for a silent session check. If it blocks real logins, the SP should retry without IsPassive.",
	},
	"InvalidNameIDPolicy": {
		"The IdP cannot provide a user identifier (NameID) in the format the SP asked for.",
		"Make the SP's requested NameID format match one the IdP is configured to send for this application, or have the SP request \"unspecified\".",
	},
	"NoAuthnContext": {
		"The IdP cannot authenticate the user in the way the SP demanded (for example a specific MFA method or password-only login).",
		"Remove or relax the SP's RequestedAuthnContext, or configure the IdP to support the requested method.",
	},
	"UnknownPrincipal": {
		"The IdP does not recognize the user.",
		"Check that the account exists in the IdP and that the user signed in with the right username or domain.",
	},
	"UnsupportedBinding": {
		"The IdP cannot reply using the binding the SP asked for.",
		"Configure the SP to request the HTTP-POST binding for its Assertion Consumer Service.",
	},
	"RequestUnsupported": {
		"The IdP does not support something in the SP's request.",
		"Compare the SP's AuthnRequest settings with what the IdP documents as supported.",
	},
	"NoAvailableIDP": {
		"No identity provider was available to handle the request (usually a proxying or discovery IdP).",
		"Check the IdP proxy or discovery-service configuration.",
	},
	"NoSupportedIDP": {
		"None of the identity providers the SP allows is supported by the proxying IdP.",
		"Check the SP's IDPList and the proxy's configuration.",
	},
	"InvalidAttrNameOrValue": {
		"The request contained an attribute name or value the IdP rejects.",
		"Review the attributes the SP requests.",
	},
	"RequestVersionTooHigh": {"The SP's SAML version is newer than the IdP supports.", "Make sure the SP sends SAML 2.0 messages."},
	"RequestVersionTooLow":  {"The SP's SAML version is older than the IdP supports.", "Make sure the SP sends SAML 2.0 messages."},
}

// maxStatusMessage caps how much of the IdP's free-text StatusMessage is
// shown. It is meant for humans, but it is still input from the file.
const maxStatusMessage = 200

func (statusNotSuccess) Check(ctx Context) []Finding {
	views := samlResponses(ctx)
	if len(views) == 0 {
		return nil
	}

	var out []Finding
	for _, v := range views {
		st := v.Resp.Status
		if st.Code == statusSuccess {
			continue
		}
		top, sub := lastPart(st.Code), lastPart(st.SubCode)

		meaning, fix := "The IdP did not report success, so no login happened.", "Check the IdP's sign-in logs for this user and time."
		if h, ok := topLevelStatus[top]; ok {
			meaning, fix = h.meaning, h.fix
		}
		// The second-level code is more specific, so it wins when known.
		if h, ok := secondLevelStatus[sub]; ok {
			meaning, fix = h.meaning, h.fix
		}
		if st.Code == "" {
			meaning = "The Response has no status code at all, so the SP cannot treat it as a successful login."
			fix = "This is an IdP bug or a damaged message. Check whether something between the IdP and the browser modified it."
		}

		f := Finding{
			RuleID:   "SAML001",
			Severity: Fail,
			Title:    "IdP returned an error instead of a login",
			Detail:   meaning,
			Fix:      fix,
			Evidence: []Evidence{
				{Label: "Response", Value: where(v.Msg)},
				{Label: "Status", Value: orNone(top)},
			},
		}
		if sub != "" {
			f.Evidence = append(f.Evidence, Evidence{Label: "Second-level status", Value: sub})
		}
		if st.Message != "" {
			f.Evidence = append(f.Evidence, Evidence{Label: "IdP message", Value: truncate(st.Message, maxStatusMessage)})
		}
		out = append(out, f)
	}

	if len(out) == 0 {
		return []Finding{passFinding("SAML001", "IdP reported success",
			fmt.Sprintf("All %s reported status Success.", plural(len(views), "SAML response")))}
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// truncate shortens s to at most n runes, marking the cut.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
