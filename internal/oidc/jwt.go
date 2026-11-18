package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// MaxJWTLen bounds the length of a token Parse will look at. Real ID and
// access tokens are a few kilobytes; anything far larger is either not a
// token or an attempt to make the decoder do a lot of work.
const MaxJWTLen = 64 << 10

// RedactedSignature replaces a JWT's signature segment when ssotrace
// redacts a capture. Parse recognizes it, so a redacted token keeps its
// diagnostic claims readable while saying plainly it can no longer verify.
const RedactedSignature = "ssotrace-redacted"

// ErrEncrypted means the value is a JWE (five segments): its claims are
// encrypted for the client and cannot be read without the client's key.
// Callers treat it as "present but uncheckable", not as malformed.
var ErrEncrypted = errors.New("jwt is encrypted (JWE); its claims cannot be read")

// JWT is a decoded JWS compact token: header and claims, plus what is
// needed to verify the signature later.
//
// Decoding a token proves nothing about it. Until a signature is verified
// against a key the user trusts, every claim here is what the token says
// about itself.
type JWT struct {
	Header Header `json:"header"`
	Claims Claims `json:"claims"`

	// signingInput is "header.payload" exactly as received: a signature
	// covers these bytes, not the decoded JSON, so re-encoding the JSON
	// would break verification.
	signingInput string
	signature    []byte
	// SignatureRedacted means ssotrace removed the signature when it
	// redacted the capture. The token was signed; it can no longer be
	// checked.
	SignatureRedacted bool `json:"signature_redacted,omitempty"`
}

// Header holds the JOSE header fields that matter for diagnosis.
type Header struct {
	Alg string `json:"alg"`           // signing algorithm, e.g. RS256; "none" means unsigned
	Typ string `json:"typ,omitempty"` // token type hint, e.g. JWT or at+jwt
	Kid string `json:"kid,omitempty"` // which key in the issuer's JWKS signed it
}

// Claims holds the registered and OIDC claims the rules check. Other claims
// are ignored: they are either application data or personal data, and
// neither explains a failed login.
type Claims struct {
	Issuer    string     `json:"iss,omitempty"`
	Subject   string     `json:"sub,omitempty"`
	Audience  []string   `json:"aud,omitempty"` // always a list; a single string is normalized
	AZP       string     `json:"azp,omitempty"` // authorized party: the client the token was issued to
	Expires   *time.Time `json:"exp,omitempty"`
	NotBefore *time.Time `json:"nbf,omitempty"`
	IssuedAt  *time.Time `json:"iat,omitempty"`

	// Nonce is compared by rules but never serialized: it ties a token to
	// one browser session, and the comparison result is what users need.
	Nonce string `json:"-"`
}

// Signed reports whether the token carries a signature at all. An "alg":
// "none" token has an empty third segment. A token whose signature was
// redacted was signed, so it counts as signed.
func (t *JWT) Signed() bool { return len(t.signature) > 0 || t.SignatureRedacted }

// wireClaims is the payload as it appears on the wire. aud and the dates
// have more than one legal shape, so they are decoded loosely here and
// normalized by Parse.
type wireClaims struct {
	Iss   string          `json:"iss"`
	Sub   string          `json:"sub"`
	Aud   json.RawMessage `json:"aud"`
	AZP   string          `json:"azp"`
	Exp   *json.Number    `json:"exp"`
	Nbf   *json.Number    `json:"nbf"`
	Iat   *json.Number    `json:"iat"`
	Nonce string          `json:"nonce"`
}

// Parse decodes a JWS compact token without verifying it.
//
// Error messages describe what is wrong in general terms and never include
// any part of the token: a malformed token may still be a live credential.
func Parse(token string) (*JWT, error) {
	if len(token) > MaxJWTLen {
		return nil, fmt.Errorf("jwt is %d bytes, over the %d-byte limit", len(token), MaxJWTLen)
	}
	parts := strings.Split(token, ".")
	switch len(parts) {
	case 3:
	case 5:
		return nil, ErrEncrypted
	default:
		return nil, fmt.Errorf("jwt has %d segments, want 3", len(parts))
	}

	headerJSON, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt header: %w", err)
	}
	payloadJSON, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt payload: %w", err)
	}
	var sig []byte
	redacted := parts[2] == RedactedSignature
	if !redacted {
		if sig, err = decodeSegment(parts[2]); err != nil {
			return nil, fmt.Errorf("jwt signature: %w", err)
		}
	}

	t := &JWT{signingInput: parts[0] + "." + parts[1], signature: sig, SignatureRedacted: redacted}
	if err := unmarshalObject(headerJSON, &t.Header); err != nil {
		return nil, fmt.Errorf("jwt header: %w", err)
	}
	if t.Header.Alg == "" {
		// RFC 7515 §4.1.1 makes alg mandatory; without it nobody can say
		// how, or whether, the token was signed.
		return nil, errors.New("jwt header: alg is missing")
	}

	var w wireClaims
	if err := unmarshalObject(payloadJSON, &w); err != nil {
		return nil, fmt.Errorf("jwt payload: %w", err)
	}
	if t.Claims, err = normalize(w); err != nil {
		return nil, fmt.Errorf("jwt payload: %w", err)
	}
	return t, nil
}

// decodeSegment decodes one base64url segment. JWS forbids padding, but a
// few libraries add it anyway; accepting it costs nothing and avoids
// telling a user a working token is malformed.
func decodeSegment(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, errors.New("not valid base64url")
	}
	return b, nil
}

// unmarshalObject decodes a JSON object into v. encoding/json keeps the
// last value when a key repeats, which is what RFC 7515 §4 allows.
//
// Errors are rewritten: encoding/json syntax errors quote input characters,
// and a type error names only the field, which is safe to show.
func unmarshalObject(data []byte, v any) error {
	trimmed := strings.TrimSpace(string(data))
	if !strings.HasPrefix(trimmed, "{") {
		return errors.New("not a JSON object")
	}
	if err := json.Unmarshal(data, v); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) && typeErr.Field != "" {
			return fmt.Errorf("claim %q has the wrong type", typeErr.Field)
		}
		return errors.New("not valid JSON")
	}
	return nil
}

func normalize(w wireClaims) (Claims, error) {
	c := Claims{Issuer: w.Iss, Subject: w.Sub, AZP: w.AZP, Nonce: w.Nonce}

	aud, err := audience(w.Aud)
	if err != nil {
		return Claims{}, err
	}
	c.Audience = aud

	for _, d := range []struct {
		name string
		in   *json.Number
		out  **time.Time
	}{
		{"exp", w.Exp, &c.Expires},
		{"nbf", w.Nbf, &c.NotBefore},
		{"iat", w.Iat, &c.IssuedAt},
	} {
		if d.in == nil {
			continue
		}
		t, err := numericDate(*d.in)
		if err != nil {
			return Claims{}, fmt.Errorf("claim %q: %w", d.name, err)
		}
		*d.out = &t
	}
	return c, nil
}

// audience accepts both shapes RFC 7519 §4.1.3 allows: a single string or
// an array of strings.
func audience(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, nil
	}
	return nil, errors.New(`claim "aud" must be a string or an array of strings`)
}

// maxNumericDate is the start of year 10000. Larger values cannot be
// represented as an RFC 3339 time and are certainly not real dates.
const maxNumericDate = 253402300800

// numericDate converts seconds since the Unix epoch (RFC 7519 §2) to a
// time. Fractional seconds are legal, so the value is read as a float.
func numericDate(n json.Number) (time.Time, error) {
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f >= maxNumericDate {
		return time.Time{}, errors.New("not a valid date (seconds since 1970)")
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC(), nil
}
