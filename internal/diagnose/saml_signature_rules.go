package diagnose

import (
	"fmt"

	"github.com/Josperdo/ssotrace/internal/flow"
	"github.com/Josperdo/ssotrace/internal/saml"
)

// The signature rules share one walk over every signature in the capture.

// signedPart is one element that can carry a signature.
type signedPart struct {
	flow  int    // index into ctx.SAML.Flows
	label string // "Response", "Assertion 1", "AuthnRequest"
	msg   *flow.SAMLMessage
	sig   saml.Signature
}

func signedParts(ctx Context) []signedPart {
	if ctx.SAML == nil {
		return nil
	}
	var out []signedPart
	for i := range ctx.SAML.Flows {
		f := &ctx.SAML.Flows[i]
		if r := f.Request; r != nil && r.Message != nil && r.Message.AuthnRequest != nil {
			out = append(out, signedPart{i, "AuthnRequest", r, r.Message.AuthnRequest.Signature})
		}
	}
	for _, v := range samlResponses(ctx) {
		out = append(out, signedPart{v.Index, "Response", v.Msg, v.Resp.Signature})
		for i, a := range v.Resp.Assertions {
			out = append(out, signedPart{v.Index, fmt.Sprintf("Assertion %d", i+1), v.Msg, a.Signature})
		}
	}
	return out
}

// unsigned is SAML007: assertion content that no signature covers. Without
// a signature, anyone who can reach the SP can write their own assertion
// and log in as anyone, so every SP must reject it.
type unsigned struct{}

func (unsigned) ID() string { return "SAML007" }

func (unsigned) Check(ctx Context) []Finding {
	var out []Finding
	checked := 0
	for _, v := range samlResponses(ctx) {
		for i, a := range v.Resp.Assertions {
			checked++
			if v.Resp.Signature.Present || a.Signature.Present {
				continue
			}
			out = append(out, Finding{
				RuleID:   "SAML007",
				Flow:     v.flowRef(),
				Severity: Fail,
				Title:    "Assertion is not signed",
				Detail: "Neither the Response nor the assertion carries a signature, so nothing proves the IdP wrote it. " +
					"SPs reject unsigned assertions, because otherwise anyone could forge a login.",
				Fix: "In the IdP's settings for this application, turn on signing of the assertion (\"Sign assertions\"), the Response, or both. " +
					"Assertion signing is the most widely accepted.",
				Evidence: []Evidence{
					{Label: "Response", Value: where(v.Msg)},
					{Label: "Assertion", Value: fmt.Sprintf("%d of %d", i+1, len(v.Resp.Assertions))},
				},
			})
		}
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("SAML007", "Assertions are signed",
			fmt.Sprintf("All %s are covered by a signature.", plural(checked, "assertion")))}
	}
	return out
}

// invalidSignature is SAML008: a signature is present but does not match
// the content. Either the message changed after the IdP signed it, or it
// was signed with a key that does not belong to the certificate inside it.
type invalidSignature struct{}

func (invalidSignature) ID() string { return "SAML008" }

func (invalidSignature) Check(ctx Context) []Finding {
	var out []Finding
	checked := 0
	for _, p := range signedParts(ctx) {
		if !p.sig.Present {
			continue
		}
		checked++
		if p.sig.Verified {
			continue
		}
		if p.sig.Error == saml.ErrNoEmbeddedCert {
			out = append(out, Finding{
				RuleID:   "SAML008",
				Flow:     flowRef(p.flow),
				Severity: Info,
				Title:    p.label + " signature could not be checked",
				Detail: "The " + p.label + " is signed, but the signature does not include the signing certificate. " +
					"Some IdPs leave it out on purpose because the SP already has it. ssotrace can only verify signatures that carry their certificate, so this one is unchecked, not invalid.",
				Fix:      "No fix needed if the SP accepts the login. If the SP reports a signature error, compare its configured IdP certificate with the IdP's current signing certificate.",
				Evidence: []Evidence{{Label: p.label, Value: where(p.msg)}},
			})
			continue
		}
		f := Finding{
			RuleID:   "SAML008",
			Flow:     flowRef(p.flow),
			Severity: Fail,
			Title:    p.label + " signature is invalid",
			Detail: "The " + p.label + " carries a signature, but it does not verify against the certificate embedded in it. " +
				"The SP will reject the message.",
			Fix: "Common causes: something between the IdP and the browser rewrote the message (a proxy, a WAF, or a browser extension); " +
				"the message was edited by hand or by a HAR sanitizer; or the IdP signed with a different key than the certificate it embeds. " +
				"Capture again directly from the browser. If it still fails, compare the IdP's current signing certificate with the one in the evidence.",
			Evidence: []Evidence{
				{Label: p.label, Value: where(p.msg)},
				{Label: "Validator says", Value: orNone(p.sig.Error)},
			},
		}
		if c := p.sig.Certificate; c != nil {
			f.Evidence = append(f.Evidence,
				Evidence{Label: "Certificate subject", Value: c.Subject},
				Evidence{Label: "Certificate SHA-256", Value: c.SHA256},
			)
		}
		out = append(out, f)
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("SAML008", "Signatures verify",
			fmt.Sprintf("All %s verify against the certificate embedded in them. "+
				"This proves the content was not changed after signing, not that the signer is the IdP you expect.",
				plural(checked, "signature")))}
	}
	return out
}

// weakAlgorithms are signature and digest algorithms considered broken or
// deprecated. SHA-1 collisions are practical since 2017, and many SPs now
// refuse SHA-1 signatures outright.
var weakAlgorithms = map[string]string{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":        "RSA-SHA1",
	"http://www.w3.org/2000/09/xmldsig#dsa-sha1":        "DSA-SHA1",
	"http://www.w3.org/2000/09/xmldsig#sha1":            "SHA-1",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-md5":    "RSA-MD5",
	"http://www.w3.org/2001/04/xmldsig-more#md5":        "MD5",
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1": "ECDSA-SHA1",
}

// weakAlgorithm is SAML010.
type weakAlgorithm struct{}

func (weakAlgorithm) ID() string { return "SAML010" }

func (weakAlgorithm) Check(ctx Context) []Finding {
	var out []Finding
	checked := 0
	for _, p := range signedParts(ctx) {
		if !p.sig.Present {
			continue
		}
		checked++
		var weak []Evidence
		if name, ok := weakAlgorithms[p.sig.Algorithm]; ok {
			weak = append(weak, Evidence{Label: "Signature algorithm", Value: name})
		}
		if name, ok := weakAlgorithms[p.sig.DigestAlgorithm]; ok {
			weak = append(weak, Evidence{Label: "Digest algorithm", Value: name})
		}
		if len(weak) == 0 {
			continue
		}
		out = append(out, Finding{
			RuleID:   "SAML010",
			Flow:     flowRef(p.flow),
			Severity: Warn,
			Title:    p.label + " uses a weak signature algorithm",
			Detail: "The " + p.label + " is signed with SHA-1 or MD5. These are no longer considered secure, " +
				"and many SPs now reject them, so this can stop working without any change on your side.",
			Fix:      "In the IdP's settings for this application, change the signature algorithm to RSA-SHA256 (and the digest to SHA-256).",
			Evidence: append([]Evidence{{Label: p.label, Value: where(p.msg)}}, weak...),
		})
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("SAML010", "Signature algorithms are strong",
			fmt.Sprintf("None of the %s uses SHA-1 or MD5.", plural(checked, "signature")))}
	}
	return out
}
