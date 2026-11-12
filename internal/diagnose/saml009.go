package diagnose

import (
	"fmt"
	"time"

	"github.com/Josperdo/ssotrace/internal/saml"
)

// certExpiry is SAML009: the certificate embedded in a signature is
// expired, not yet valid, or expires soon, judged at the time the message
// was sent.
//
// It is a WARN, not a FAIL: many SPs pin the IdP's certificate and ignore
// its dates entirely, while others reject an expired one. Either way an
// expiring certificate is the usual first step of a certificate rollover,
// the most common cause of "SSO suddenly broke for everyone".
type certExpiry struct{}

func (certExpiry) ID() string { return "SAML009" }

// expiryWarning is how close to expiry a certificate must be to warn.
const expiryWarning = 30 * 24 * time.Hour

func (certExpiry) Check(ctx Context) []Finding {
	var out []Finding
	seen := map[string]bool{} // fingerprints: one finding per certificate
	checked := 0
	for _, p := range signedParts(ctx) {
		c := p.sig.Certificate
		if c == nil || seen[c.SHA256] {
			continue
		}
		at, ok := sentAt(ctx, p.msg)
		notAfter, err := time.Parse(time.RFC3339, c.NotAfter)
		if !ok || err != nil {
			continue
		}
		seen[c.SHA256] = true
		checked++

		ev := []Evidence{
			{Label: "Signed element", Value: p.label + ", " + where(p.msg)},
			{Label: "Certificate subject", Value: c.Subject},
			{Label: "Certificate SHA-256", Value: c.SHA256},
			{Label: "Valid from", Value: c.NotBefore},
			{Label: "Valid until", Value: c.NotAfter},
			{Label: "Message sent at", Value: at.UTC().Format(time.RFC3339)},
		}
		switch c.ValidityAtCapture {
		case saml.ValidityExpired:
			out = append(out, Finding{
				RuleID:   "SAML009",
				Severity: Warn,
				Title:    "IdP signing certificate had expired",
				Detail: fmt.Sprintf("The certificate that signed this message expired %s before the message was sent. "+
					"SPs that check certificate dates will reject the login; SPs that only pin the certificate will still accept it.",
					humanDuration(at.Sub(notAfter))),
				Fix: "Create a new signing certificate in the IdP, then give the new certificate (or the IdP's updated metadata) to the SP. " +
					"Do both before switching the IdP over, or logins will fail in between.",
				Evidence: ev,
			})
		case saml.ValidityNotYetValid:
			out = append(out, Finding{
				RuleID:   "SAML009",
				Severity: Warn,
				Title:    "IdP signing certificate was not yet valid",
				Detail: "The certificate that signed this message was not valid yet when the message was sent. " +
					"Either it was issued with a future start date, or a clock (the IdP's or the user's) is wrong.",
				Fix:      "Check the clocks on the IdP and on the user's machine, then the certificate's start date.",
				Evidence: ev,
			})
		case saml.ValidityValid:
			left := notAfter.Sub(at)
			if left > expiryWarning {
				continue
			}
			out = append(out, Finding{
				RuleID:   "SAML009",
				Severity: Warn,
				Title:    "IdP signing certificate expires soon",
				Detail: fmt.Sprintf("The certificate that signed this message expires %s after the message was sent. "+
					"When it expires, SPs that check certificate dates will start rejecting logins.", humanDays(left)),
				Fix: "Plan the rollover now: create the new signing certificate in the IdP, give it to the SP (many SPs accept two at once), " +
					"then switch the IdP over before the old one expires.",
				Evidence: ev,
			})
		}
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("SAML009", "IdP signing certificate is within its validity period",
			fmt.Sprintf("Checked %s; none is expired or expires within 30 days of the capture.", plural(checked, "certificate")))}
	}
	return out
}

// humanDays renders a long duration in days, which is how people plan
// certificate rollovers.
func humanDays(d time.Duration) string {
	if d < 24*time.Hour {
		return "less than a day"
	}
	// Rounded, not truncated: 9 days 23 hours reads as "10 days".
	return plural(int(d.Round(24*time.Hour).Hours()/24), "day")
}
