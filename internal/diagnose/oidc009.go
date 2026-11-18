package diagnose

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Josperdo/ssotrace/internal/oidc"
)

// idTokenSignature is OIDC009: the ID token's signature checked against
// the keys the user trusts (--jwks, --fetch-jwks).
//
// Decoding a token proves nothing, so without keys this rule says the
// signature was not checked rather than guessing. The keys come from the
// user, not the capture, so a verified signature here means the IdP
// really issued the token, not just that it is intact.
type idTokenSignature struct{}

func (idTokenSignature) ID() string { return "OIDC009" }

func (idTokenSignature) Check(ctx Context) []Finding {
	views := idTokens(ctx)
	if len(views) == 0 {
		return nil
	}
	if ctx.JWKS == nil {
		return []Finding{notChecked(views)}
	}
	var out []Finding
	verified := 0
	for _, v := range views {
		ev := []Evidence{
			{Label: v.label(), Value: sentWhere(v.Sent)},
			{Label: "alg", Value: truncate(v.Token.Header.Alg, 32)},
		}
		if kid := v.Token.Header.Kid; kid != "" {
			ev = append(ev, Evidence{Label: "kid", Value: truncate(kid, 64)})
		}
		if !v.Token.Signed() || strings.EqualFold(v.Token.Header.Alg, "none") {
			out = append(out, Finding{
				RuleID: "OIDC009", OIDCFlow: v.flowRef(), Severity: Fail,
				Title:    "ID token is unsigned",
				Detail:   "The ID token has no signature. A client that verifies ID tokens, as it must, rejects it.",
				Fix:      "Configure the IdP to sign ID tokens (RS256 or ES256) for this client.",
				Evidence: ev,
			})
			continue
		}
		res := v.Token.Verify(ctx.JWKS)
		switch res.Status {
		case oidc.Verified:
			verified++
		case oidc.Invalid:
			out = append(out, Finding{
				RuleID: "OIDC009", OIDCFlow: v.flowRef(), Severity: Fail,
				Title: "ID token signature is invalid",
				Detail: "A key you trust fits this token, but its signature does not match. Either the token was altered after signing, " +
					"or the IdP signed it with a different key that reuses the same key ID.",
				Fix: "Make sure the key set you supplied is the IdP's current one, from its jwks_uri. If it is, treat the token as forged " +
					"and find where it was changed between the IdP and the browser.",
				Evidence: ev,
			})
		default:
			var fix string
			switch {
			case v.Token.SignatureRedacted:
				fix = "This capture was redacted, which removes signatures. Check the signature on the original capture, before redaction."
			case strings.HasPrefix(v.Token.Header.Alg, "HS"):
				fix = "Nothing to fix in the capture. Only the IdP and the client hold the shared secret, so only the client can check this signature."
			case v.Token.Header.Kid != "":
				fix = "If the key set you supplied is current, the IdP signed this token with a key it no longer publishes, or the token did not come from this IdP. " +
					"Refresh the key set from the IdP's jwks_uri and compare the kid."
			default:
				fix = "Supply the IdP's current key set with --fetch-jwks and its jwks_uri."
			}
			out = append(out, Finding{
				RuleID: "OIDC009", OIDCFlow: v.flowRef(), Severity: Info,
				Title:    "ID token signature could not be checked",
				Detail:   "ssotrace could not check this signature: " + res.Reason + ".",
				Fix:      fix,
				Evidence: ev,
			})
		}
	}
	if len(out) == 0 {
		return []Finding{passFinding("OIDC009", "ID token signatures verified",
			fmt.Sprintf("Verified %s against the keys you supplied.", plural(verified, "ID token")))}
	}
	return out
}

// notChecked is the single finding for a run without keys: one note for
// the capture, not one per token, naming where to get the keys.
func notChecked(views []tokenView) Finding {
	var issuers []string
	for _, v := range views {
		if iss := v.Token.Claims.Issuer; iss != "" && !slices.Contains(issuers, iss) {
			issuers = append(issuers, iss)
		}
	}
	f := Finding{
		RuleID:   "OIDC009",
		Severity: Info,
		Title:    "ID token signatures not checked",
		Detail: fmt.Sprintf("The capture has %s, but no keys were supplied, so ssotrace decoded the tokens without checking who signed them. "+
			"Every claim it reports is what the token says about itself.", plural(len(views), "ID token")),
		Fix: "To check signatures, run again with --fetch-jwks and the IdP's jwks_uri (listed in the issuer's /.well-known/openid-configuration; " +
			"for Keycloak, {issuer}/protocol/openid-connect/certs), or save that key set and pass it with --jwks.",
	}
	for _, iss := range issuers {
		f.Evidence = append(f.Evidence, Evidence{Label: "Issuer", Value: truncate(iss, 200)})
	}
	return f
}
