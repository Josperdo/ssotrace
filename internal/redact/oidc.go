package redact

import (
	"encoding/json"
	"strings"

	"github.com/Josperdo/ssotrace/internal/diagnose"
	"github.com/Josperdo/ssotrace/internal/har"
)

// tokenResponseKeys mark a JSON body as an OAuth token endpoint response.
// Error-only bodies are recognized by a standard "error" value instead.
var tokenResponseKeys = []string{"access_token", "id_token", "refresh_token", "token_type"}

// tokenResponse redacts a token endpoint's JSON answer instead of dropping
// it, because the ID token in it is what OIDC004, OIDC005, OIDC006, and
// OIDC009 check. The result is built from an allowlist:
//
//   - id_token and access_token go through the JWT redactor (diagnostic
//     claims kept, identifying claims masked, signature removed; an opaque
//     access token becomes [redacted]),
//   - refresh_token becomes [redacted], so its presence is still visible,
//   - error keeps only a standard OAuth value, and error_description only
//     its codes,
//   - token_type, scope, and the lifetimes are kept,
//   - everything else is dropped.
//
// It reports false for any other body, which then gets the usual stub.
func (r *redactor) tokenResponse(c *har.Content) (string, bool) {
	if !strings.Contains(strings.ToLower(c.MimeType), "json") {
		return "", false
	}
	raw, err := c.Bytes()
	if err != nil {
		return "", false
	}
	var in map[string]any
	if json.Unmarshal(raw, &in) != nil {
		return "", false
	}
	if !isTokenResponse(in) {
		return "", false
	}

	out := map[string]any{}
	for k, v := range in {
		s, isString := v.(string)
		switch k {
		case "id_token", "access_token":
			if isString {
				out[k] = r.jwt(s)
			}
		case "refresh_token":
			out[k] = Redacted
		case "error":
			if isString && diagnose.IsOAuthError(s) {
				out[k] = s
			}
		case "error_description":
			if isString {
				out[k] = keepCodesOnly(s)
			}
		case "token_type", "scope":
			if isString {
				out[k] = r.scrub(s)
			}
		case "expires_in", "refresh_expires_in":
			if _, isNumber := v.(float64); isNumber {
				out[k] = v
			}
		}
	}
	// encoding/json sorts map keys, so the output is deterministic.
	b, err := json.Marshal(out)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func isTokenResponse(m map[string]any) bool {
	for _, k := range tokenResponseKeys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	e, ok := m["error"].(string)
	return ok && diagnose.IsOAuthError(e)
}
