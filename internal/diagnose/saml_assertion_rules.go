package diagnose

import (
	"fmt"
	"strconv"
)

// encryptedAssertion is SAML011: the assertion is encrypted for the SP, so
// ssotrace (rightly) cannot read it. Informational: encryption is good
// practice, but it limits what can be diagnosed from a HAR.
type encryptedAssertion struct{}

func (encryptedAssertion) ID() string { return "SAML011" }

func (encryptedAssertion) Check(ctx Context) []Finding {
	var out []Finding
	for _, v := range samlResponses(ctx) {
		if v.Resp.EncryptedAssertions == 0 {
			continue
		}
		out = append(out, Finding{
			RuleID:   "SAML011",
			Flow:     v.flowRef(),
			Severity: Info,
			Title:    "Assertion is encrypted",
			Detail: "The assertion is encrypted with the SP's public key, so only the SP can read it. " +
				"ssotrace can still check the Response status, Destination, and the Response's own signature, " +
				"but not the user identifier, audience, validity times, or attributes inside the assertion.",
			Fix: "No fix needed. For a full diagnosis, temporarily turn off assertion encryption for this application in a test environment, " +
				"or check the SP's logs, which see the decrypted assertion.",
			Evidence: []Evidence{
				{Label: "Response", Value: where(v.Msg)},
				{Label: "Encrypted assertions", Value: strconv.Itoa(v.Resp.EncryptedAssertions)},
			},
		})
	}
	return out
}

// unspecifiedNameID is the NameID format that means "anything goes".
const unspecifiedNameID = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

// nameIDProblems is SAML012: the user identifier is missing, or in a
// different format from the one the SP asked for.
type nameIDProblems struct{}

func (nameIDProblems) ID() string { return "SAML012" }

func (nameIDProblems) Check(ctx Context) []Finding {
	var out []Finding
	checked := 0
	for _, v := range samlResponses(ctx) {
		var wantFormat string
		if r := v.request(); r != nil && r.NameIDPolicy != nil {
			wantFormat = r.NameIDPolicy.Format
		}
		for _, a := range v.Resp.Assertions {
			checked++
			nid := a.Subject.NameID
			if nid.Value == "" {
				out = append(out, Finding{
					RuleID:   "SAML012",
					Flow:     v.flowRef(),
					Severity: Warn,
					Title:    "Assertion has no NameID",
					Detail: "The assertion does not identify the user with a NameID. Most SPs use the NameID to find the account, " +
						"so they cannot log the user in unless they are set up to read an attribute instead.",
					Fix:      "In the IdP's settings for this application, choose which user property to send as the NameID (often the email address or username).",
					Evidence: []Evidence{{Label: "Response", Value: where(v.Msg)}},
				})
				continue
			}
			if wantFormat == "" || wantFormat == unspecifiedNameID || nid.Format == "" || nid.Format == wantFormat {
				continue
			}
			out = append(out, Finding{
				RuleID:   "SAML012",
				Flow:     v.flowRef(),
				Severity: Fail,
				Title:    "NameID format differs from what the SP requested",
				Detail: fmt.Sprintf("The SP asked for a %s NameID, but the IdP sent a %s one. "+
					"SPs that enforce the format reject the login; others may look up the wrong account.", lastPart(wantFormat), lastPart(nid.Format)),
				Fix: "Make the two sides agree: set the IdP's NameID format for this application to the one the SP requests, " +
					"or change the SP to request the format the IdP sends (or \"unspecified\").",
				Evidence: []Evidence{
					{Label: "Response", Value: where(v.Msg)},
					{Label: "Requested format", Value: wantFormat},
					{Label: "Format sent", Value: nid.Format},
				},
			})
		}
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("SAML012", "NameID present and in the requested format",
			fmt.Sprintf("Checked %s.", plural(checked, "assertion")))}
	}
	return out
}

// multipleAssertions is SAML014: a Response with more than one assertion.
// The SAML profile allows it, but real IdPs send one, and the classic XML
// signature wrapping attacks work by adding a second assertion for a
// careless SP to read. Worth a human look.
type multipleAssertions struct{}

func (multipleAssertions) ID() string { return "SAML014" }

func (multipleAssertions) Check(ctx Context) []Finding {
	var out []Finding
	views := samlResponses(ctx)
	for _, v := range views {
		total := len(v.Resp.Assertions) + v.Resp.EncryptedAssertions
		if total <= 1 {
			continue
		}
		verified := 0
		for _, a := range v.Resp.Assertions {
			if a.Verified {
				verified++
			}
		}
		out = append(out, Finding{
			RuleID:   "SAML014",
			Flow:     v.flowRef(),
			Severity: Warn,
			Title:    "Response contains more than one assertion",
			Detail: "Identity providers normally send exactly one assertion. Extra assertions are how XML signature wrapping attacks " +
				"smuggle a forged identity past SPs that check one assertion's signature but read another's contents.",
			Fix: "If you did not expect this, treat the capture as suspicious: find out where the Response was modified. " +
				"Make sure the SP accepts exactly one assertion and reads only the one its signature check validated.",
			Evidence: []Evidence{
				{Label: "Response", Value: where(v.Msg)},
				{Label: "Assertions", Value: strconv.Itoa(total)},
				{Label: "Verified by a signature", Value: fmt.Sprintf("%d of %d readable", verified, len(v.Resp.Assertions))},
			},
		})
	}
	if len(out) == 0 && len(views) > 0 {
		return []Finding{passFinding("SAML014", "One assertion per response",
			fmt.Sprintf("Checked %s.", plural(len(views), "SAML response")))}
	}
	return out
}
