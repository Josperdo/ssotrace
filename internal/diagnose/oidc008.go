package diagnose

import (
	"fmt"
	"strings"
)

// insecurePatterns is OIDC008: the sign-in works but uses a pattern
// current OAuth security guidance (RFC 9700, the OAuth 2.0 Security Best
// Current Practice) says to avoid. These are warnings: they do not explain
// a failure, but they are worth fixing before they become one.
type insecurePatterns struct{}

func (insecurePatterns) ID() string { return "OIDC008" }

func (insecurePatterns) Check(ctx Context) []Finding {
	flows := oidcFlows(ctx)
	var out []Finding
	checked := 0
	add := func(i int, sev Severity, title, detail, fix string, ev ...Evidence) {
		out = append(out, Finding{RuleID: "OIDC008", OIDCFlow: flowRef(i), Severity: sev, Title: title, Detail: detail, Fix: fix, Evidence: ev})
	}
	for i := range flows {
		f := &flows[i]
		if a := f.Authorization; a != nil {
			checked++
			p := a.Params
			where := Evidence{Label: "Authorization request", Value: sentWhere(a.Sent)}
			rt := Evidence{Label: "response_type", Value: truncate(p.ResponseType, 64)}

			if hasWord(p.ResponseType, "token") {
				add(i, Warn, "Implicit flow returns access tokens in the browser",
					"response_type includes token, so the access token travels in the URL, where browser history, logs, and the Referer header can leak it. "+
						"Current OAuth guidance no longer allows this flow.",
					"Switch the application to response_type=code with PKCE, then turn off the implicit flow for this client in the IdP.",
					where, rt)
			}

			if hasWord(p.ResponseType, "code") {
				public := f.Token != nil && !f.Token.Request.HasClientSecret
				switch {
				case !p.HasCodeChallenge && public:
					add(i, Warn, "Browser app uses authorization codes without PKCE",
						"This application redeems its code from the browser, so it cannot keep a client secret. Without PKCE, anyone who intercepts the code can redeem it.",
						"Send a code_challenge (method S256) with the authorization request and the matching code_verifier with the token request, "+
							"then require PKCE for this client in the IdP.",
						where, rt)
				case !p.HasCodeChallenge:
					add(i, Info, "Authorization code flow without PKCE",
						"No code_challenge was sent. Current guidance recommends PKCE for every client, including those with a client secret.",
						"Add PKCE (S256) to the application's sign-in when convenient.",
						where, rt)
				case p.CodeChallengeMethod == "" || strings.EqualFold(p.CodeChallengeMethod, "plain"):
					add(i, Warn, "PKCE uses the plain method",
						"The code_challenge is sent as is (method plain, the default when none is named), so intercepting the authorization request reveals the verifier.",
						"Use code_challenge_method=S256.",
						where, Evidence{Label: "code_challenge_method", Value: challengeMethod(p.CodeChallengeMethod)})
				}
			}
		}
		if t := f.Token; t != nil && t.Request.HasClientSecret {
			add(i, Warn, "Client secret sent from the browser",
				"The browser itself sent client_secret to the token endpoint, so anyone using the application can read it. A secret in a browser app is not secret.",
				"Make this a public client in the IdP (Keycloak: turn \"Client authentication\" off), use PKCE, and rotate the exposed secret.",
				Evidence{Label: "Token request", Value: sentWhere(t.Sent)})
		}
	}
	for _, v := range tokens(ctx, true) {
		if strings.EqualFold(v.Token.Header.Alg, "none") {
			add(v.Index, Warn, cap1(v.Kind)+" is unsigned (alg none)",
				"The token has no signature, so anyone could have written it. A client that accepts it can be signed in as anyone.",
				"Configure the IdP to sign tokens (RS256 or ES256), and make sure the application rejects alg none.",
				Evidence{Label: v.label(), Value: sentWhere(v.Sent)})
		}
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("OIDC008", "No insecure OAuth patterns found",
			fmt.Sprintf("Checked %s for the implicit flow, missing PKCE, browser client secrets, and unsigned tokens.", plural(checked, "sign-in")))}
	}
	return out
}

func challengeMethod(m string) string {
	if m == "" {
		return "(not sent; defaults to plain)"
	}
	return truncate(m, 32)
}
