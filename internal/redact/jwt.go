package redact

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// jwtKeepClaims are claims that explain why a token was rejected (wrong
// issuer or audience, expired, not yet valid) without identifying the
// user. Everything not listed here is dropped.
var jwtKeepClaims = map[string]bool{
	"iss": true, "aud": true, "exp": true, "iat": true, "nbf": true,
	"azp": true, "typ": true, "acr": true, "amr": true, "ver": true,
}

// jwtMaskClaims identify a user or session. They are kept as salted
// hashes so two tokens for the same user still match each other.
var jwtMaskClaims = map[string]bool{"sub": true, "nonce": true, "sid": true}

// jwtKeepHeader is the part of a JWT header worth keeping: the algorithm
// and the key ID say how the token was signed and with which key.
var jwtKeepHeader = map[string]bool{"alg": true, "typ": true, "kid": true}

// jwt redacts a JWT: diagnostic claims stay, identifying claims are
// masked, everything else and the signature are removed. The result is
// still three dot-separated segments, so tools recognize it as a JWT, but
// its signature segment is a marker and it can never verify. A value that
// is not a readable JWT is replaced entirely (opaque tokens are secrets
// with nothing diagnostic to keep).
func (r *redactor) jwt(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return Redacted
	}
	header, ok1 := r.jwtSegment(parts[0], jwtKeepHeader, nil)
	payload, ok2 := r.jwtSegment(parts[1], jwtKeepClaims, jwtMaskClaims)
	if !ok1 || !ok2 {
		return Redacted
	}
	return header + "." + payload + "." + jwtSigMarker
}

// jwtSegment decodes one base64url JSON segment, keeps only allowed keys
// (masking those in mask), and re-encodes it.
func (r *redactor) jwtSegment(seg string, keep, mask map[string]bool) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return "", false
	}
	var in map[string]any
	if err := json.Unmarshal(raw, &in); err != nil {
		return "", false
	}
	out := map[string]any{}
	for k, v := range in {
		switch {
		case keep[k]:
			out[k] = v
		case mask[k]:
			if s, ok := v.(string); ok {
				out[k] = r.mask(s)
			}
		}
	}
	// encoding/json sorts map keys, so the output is deterministic.
	b, err := json.Marshal(out)
	if err != nil {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(b), true
}
