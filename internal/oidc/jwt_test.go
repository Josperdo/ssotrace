package oidc

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// planted appears inside malformed tokens so tests can check that error
// messages never echo token content.
const planted = "PLANTED-SECRET-VALUE"

func seg(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// token builds a compact JWS from raw header and payload JSON. The
// signature is arbitrary bytes: Parse does not verify.
func token(header, payload string) string {
	return seg(header) + "." + seg(payload) + "." + seg("sig")
}

const rs256 = `{"alg":"RS256","typ":"JWT","kid":"key-1"}`

func TestParseClaims(t *testing.T) {
	exp := time.Date(2026, 1, 15, 11, 0, 0, 0, time.UTC)
	tok := token(rs256, `{
		"iss":"https://idp.example.com/realms/lab",
		"sub":"00000000-0000-4000-8000-000000000001",
		"aud":"web-app",
		"azp":"web-app",
		"exp":1768474800,
		"nbf":1768471200,
		"iat":1768471200.5,
		"nonce":"n-0S6_WzA2Mj",
		"email":"user@example.com"
	}`)

	got, err := Parse(tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Header != (Header{Alg: "RS256", Typ: "JWT", Kid: "key-1"}) {
		t.Errorf("header = %+v", got.Header)
	}
	c := got.Claims
	if c.Issuer != "https://idp.example.com/realms/lab" || c.AZP != "web-app" || c.Nonce != "n-0S6_WzA2Mj" {
		t.Errorf("claims = %+v", c)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "web-app" {
		t.Errorf("aud = %v, want [web-app]", c.Audience)
	}
	if c.Expires == nil || !c.Expires.Equal(exp) {
		t.Errorf("exp = %v, want %v", c.Expires, exp)
	}
	if c.IssuedAt == nil || c.IssuedAt.Nanosecond() != 500_000_000 {
		t.Errorf("iat = %v, want half a second past", c.IssuedAt)
	}
	if !got.Signed() {
		t.Error("Signed() = false for a token with a signature")
	}
	if got.signingInput != strings.Join(strings.Split(tok, ".")[:2], ".") {
		t.Error("signingInput is not the first two segments as received")
	}
}

func TestParseShapes(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		check   func(t *testing.T, j *JWT)
		wantErr string // "" means accepted
	}{
		{
			name:  "aud as array",
			token: token(rs256, `{"aud":["web-app","api"]}`),
			check: func(t *testing.T, j *JWT) {
				if len(j.Claims.Audience) != 2 {
					t.Errorf("aud = %v", j.Claims.Audience)
				}
			},
		},
		{
			name:  "alg none is parsed, not rejected",
			token: seg(`{"alg":"none"}`) + "." + seg(`{"sub":"x"}`) + ".",
			check: func(t *testing.T, j *JWT) {
				if j.Signed() || j.Header.Alg != "none" {
					t.Errorf("Signed() = %v, alg = %q", j.Signed(), j.Header.Alg)
				}
			},
		},
		{
			name:  "padded base64 accepted",
			token: base64.URLEncoding.EncodeToString([]byte(rs256)) + "." + base64.URLEncoding.EncodeToString([]byte(`{"iss":"a"}`)) + "." + seg("s"),
		},
		{name: "two segments", token: seg(rs256) + "." + seg(`{}`), wantErr: "2 segments"},
		{name: "not a token", token: planted, wantErr: "1 segments"},
		{name: "header not base64", token: planted + "!." + seg(`{}`) + ".", wantErr: "header: not valid base64url"},
		{name: "header not JSON", token: token(planted, `{}`), wantErr: "header: not a JSON object"},
		{name: "header broken JSON", token: token(`{"alg":"`+planted, `{}`), wantErr: "header: not valid JSON"},
		{name: "alg missing", token: token(`{"typ":"JWT"}`, `{}`), wantErr: "alg is missing"},
		{name: "payload is array", token: token(rs256, `["`+planted+`"]`), wantErr: "payload: not a JSON object"},
		{name: "claim wrong type", token: token(rs256, `{"iss":42}`), wantErr: `claim "iss" has the wrong type`},
		{name: "aud wrong type", token: token(rs256, `{"aud":{"x":"`+planted+`"}}`), wantErr: `"aud" must be`},
		{name: "exp negative", token: token(rs256, `{"exp":-1}`), wantErr: `claim "exp": not a valid date`},
		{name: "exp too large", token: token(rs256, `{"exp":1e300}`), wantErr: `claim "exp": not a valid date`},
		{name: "too long", token: strings.Repeat("a", MaxJWTLen+1), wantErr: "over the"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, err := Parse(tt.token)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				if tt.check != nil {
					tt.check(t, j)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), planted) {
				t.Errorf("error %q leaks token content", err)
			}
		})
	}
}

func TestParseEncrypted(t *testing.T) {
	jwe := strings.Join([]string{seg(`{"alg":"RSA-OAEP","enc":"A256GCM"}`), seg("k"), seg("iv"), seg("ct"), seg("tag")}, ".")
	if _, err := Parse(jwe); !errors.Is(err, ErrEncrypted) {
		t.Fatalf("error = %v, want ErrEncrypted", err)
	}
}

// TestParseRedacted: a token redacted by ssotrace keeps its claims
// readable and says its signature is gone, rather than failing to parse.
func TestParseRedacted(t *testing.T) {
	tok, err := Parse(seg(rs256) + "." + seg(`{"aud":"web-app"}`) + "." + RedactedSignature)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !tok.SignatureRedacted || !tok.Signed() || tok.Claims.Audience[0] != "web-app" {
		t.Errorf("token = %+v", tok)
	}
	if v := tok.Verify(&KeySet{Keys: []Key{{ID: "key-1"}}}); v.Status != Unchecked || !strings.Contains(v.Reason, "redacted") {
		t.Errorf("Verify = %+v, want unchecked because redacted", v)
	}
}
