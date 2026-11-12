package diagnose

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// signerMismatch is SAML013: a message was signed by a certificate other
// than the one the user trusts for this IdP (--idp-cert).
//
// This is the difference between integrity and trust. A signature that
// verifies proves the message was not altered after signing; only
// comparing the signer with a certificate obtained independently proves
// who signed it. Without --idp-cert the rule says so instead of guessing.
type signerMismatch struct{}

func (signerMismatch) ID() string { return "SAML013" }

func (signerMismatch) Check(ctx Context) []Finding {
	// Collect each distinct signing certificate once, in capture order.
	type signer struct {
		part signedPart
		fp   string
	}
	var signers []signer
	seen := map[string]bool{}
	for _, p := range signedParts(ctx) {
		if c := p.sig.Certificate; c != nil && !seen[c.SHA256] {
			seen[c.SHA256] = true
			signers = append(signers, signer{p, c.SHA256})
		}
	}
	if len(signers) == 0 {
		return nil
	}

	if len(ctx.IDPCerts) == 0 {
		fps := make([]string, 0, len(signers))
		for _, s := range signers {
			fps = append(fps, s.fp)
		}
		return []Finding{{
			RuleID:   "SAML013",
			Severity: Info,
			Title:    "Signer not checked against a trusted certificate",
			Detail: "Signatures in this capture were checked only against the certificate embedded in each message. " +
				"That proves the content was not altered after signing, not that your IdP signed it: anyone can sign with their own key and embed their own certificate.",
			Fix: "To check who signed, run again with --idp-cert and the IdP's signing certificate, taken from the IdP's metadata or admin console (not from this capture). " +
				"This also detects certificate rollovers.",
			Evidence: []Evidence{{Label: "Signing certificate SHA-256", Value: strings.Join(fps, ", ")}},
		}}
	}

	trusted := map[string]bool{}
	var trustedFPs []string
	for _, c := range ctx.IDPCerts {
		sum := sha256.Sum256(c.Raw)
		fp := strings.ToUpper(hex.EncodeToString(sum[:]))
		trusted[fp] = true
		trustedFPs = append(trustedFPs, fp)
	}

	var out []Finding
	for _, s := range signers {
		if trusted[s.fp] {
			continue
		}
		c := s.part.sig.Certificate
		out = append(out, Finding{
			RuleID:   "SAML013",
			Severity: Fail,
			Title:    "Signed by a different certificate than the one you trust",
			Detail: "The message was signed with a certificate that does not match the one supplied with --idp-cert. " +
				"Most often the IdP rolled over to a new signing certificate and the SP still has the old one. " +
				"Less often, the message did not come from your IdP at all.",
			Fix: "Compare the certificate below with the IdP's current signing certificate. If it is the IdP's new certificate, " +
				"update the SP (upload the new certificate or refresh the IdP metadata). If the IdP does not recognize it, treat the message as forged.",
			Evidence: []Evidence{
				{Label: "Signed element", Value: s.part.label + ", " + where(s.part.msg)},
				{Label: "Signing certificate subject", Value: c.Subject},
				{Label: "Signing certificate SHA-256", Value: s.fp},
				{Label: "Signing certificate valid", Value: c.NotBefore + " to " + c.NotAfter},
				{Label: "Trusted certificate SHA-256", Value: strings.Join(trustedFPs, ", ")},
			},
		})
	}
	if len(out) == 0 {
		return []Finding{passFinding("SAML013", "Signed by the certificate you trust",
			fmt.Sprintf("All %s in the capture match a certificate supplied with --idp-cert.", plural(len(signers), "signing certificate")))}
	}
	return out
}
