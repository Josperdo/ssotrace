package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/Josperdo/ssotrace/internal/testutil"
)

var b64 = base64.RawURLEncoding.EncodeToString

// signer produces a JWS signature over input for one algorithm.
type signer func(t *testing.T, input []byte) []byte

func signed(t *testing.T, header map[string]string, claims string, sign signer) string {
	t.Helper()
	h, _ := json.Marshal(header)
	input := b64(h) + "." + b64([]byte(claims))
	return input + "." + b64(sign(t, []byte(input)))
}

func rsaSigner(key *rsa.PrivateKey, h crypto.Hash, pss bool) signer {
	return func(t *testing.T, input []byte) []byte {
		var sig []byte
		var err error
		if pss {
			sig, err = rsa.SignPSS(rand.Reader, key, h, digest(h, input), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, key, h, digest(h, input))
		}
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
}

// ecSigner emits R||S at fixed width, the JWS format.
func ecSigner(key *ecdsa.PrivateKey, h crypto.Hash) signer {
	return func(t *testing.T, input []byte) []byte {
		r, s, err := ecdsa.Sign(rand.Reader, key, digest(h, input))
		if err != nil {
			t.Fatal(err)
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out
	}
}

func edSigner(key ed25519.PrivateKey) signer {
	return func(_ *testing.T, input []byte) []byte { return ed25519.Sign(key, input) }
}

func rsaJWK(kid string, pub *rsa.PublicKey) map[string]string {
	return map[string]string{"kty": "RSA", "kid": kid, "n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes())}
}

func ecJWK(kid, crv string, pub *ecdsa.PublicKey) map[string]string {
	raw, _ := pub.Bytes() // 0x04 || X || Y
	size := (len(raw) - 1) / 2
	return map[string]string{"kty": "EC", "kid": kid, "crv": crv, "x": b64(raw[1 : 1+size]), "y": b64(raw[1+size:])}
}

func jwks(t *testing.T, keys ...map[string]string) *KeySet {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"keys": keys})
	ks, err := ParseJWKS(b)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	return ks
}

func TestVerify(t *testing.T) {
	rsaKey := testutil.NewKeyPair(t, "idp.example.com").Key
	otherRSA := testutil.NewKeyPair(t, "other.example.com").Key
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	keys := jwks(t,
		rsaJWK("rsa-1", &rsaKey.PublicKey),
		ecJWK("ec-256", "P-256", &p256.PublicKey),
		ecJWK("ec-384", "P-384", &p384.PublicKey),
		map[string]string{"kty": "OKP", "kid": "ed-1", "crv": "Ed25519", "x": b64(edPub)},
	)
	const claims = `{"iss":"https://idp.example.com","aud":"web-app"}`
	hdr := func(alg, kid string) map[string]string { return map[string]string{"alg": alg, "kid": kid} }

	tests := []struct {
		name  string
		token string
		keys  *KeySet
		want  VerifyStatus
		why   string // substring of Reason, for non-verified outcomes
	}{
		{name: "RS256", token: signed(t, hdr("RS256", "rsa-1"), claims, rsaSigner(rsaKey, crypto.SHA256, false)), want: Verified},
		{name: "RS512", token: signed(t, hdr("RS512", "rsa-1"), claims, rsaSigner(rsaKey, crypto.SHA512, false)), want: Verified},
		{name: "PS256", token: signed(t, hdr("PS256", "rsa-1"), claims, rsaSigner(rsaKey, crypto.SHA256, true)), want: Verified},
		{name: "ES256", token: signed(t, hdr("ES256", "ec-256"), claims, ecSigner(p256, crypto.SHA256)), want: Verified},
		{name: "ES384", token: signed(t, hdr("ES384", "ec-384"), claims, ecSigner(p384, crypto.SHA384)), want: Verified},
		{name: "EdDSA", token: signed(t, hdr("EdDSA", "ed-1"), claims, edSigner(edPriv)), want: Verified},
		{name: "no kid tries every fitting key", token: signed(t, map[string]string{"alg": "RS256"}, claims, rsaSigner(rsaKey, crypto.SHA256, false)), want: Verified},
		{
			name:  "signed by a different key with the same kid",
			token: signed(t, hdr("RS256", "rsa-1"), claims, rsaSigner(otherRSA, crypto.SHA256, false)),
			want:  Invalid, why: "does not match",
		},
		{
			name:  "unknown kid",
			token: signed(t, hdr("RS256", "rotated-key"), claims, rsaSigner(rsaKey, crypto.SHA256, false)),
			want:  Unchecked, why: "kid rotated-key",
		},
		{
			// The confusion attack: claim HS256 so the RSA public key is used
			// as an HMAC secret. It must never be attempted.
			name:  "HS256 is never checked with a public key",
			token: signed(t, hdr("HS256", "rsa-1"), claims, func(*testing.T, []byte) []byte { return []byte("mac") }),
			want:  Unchecked, why: "shared secret",
		},
		{
			name:  "curve must match alg",
			token: signed(t, hdr("ES256", "ec-384"), claims, ecSigner(p384, crypto.SHA256)),
			want:  Unchecked, why: "no trusted ES256 key",
		},
		{name: "alg none", token: b64([]byte(`{"alg":"none"}`)) + "." + b64([]byte(claims)) + ".", want: Unchecked, why: "unsigned"},
		{name: "no keys", token: signed(t, hdr("RS256", "rsa-1"), claims, rsaSigner(rsaKey, crypto.SHA256, false)), keys: &KeySet{}, want: Unchecked, why: "no trusted keys"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := Parse(tt.token)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			ks := keys
			if tt.keys != nil {
				ks = tt.keys
			}
			got := tok.Verify(ks)
			if got.Status != tt.want || !strings.Contains(got.Reason, tt.why) {
				t.Errorf("Verify = %+v, want %s with reason containing %q", got, tt.want, tt.why)
			}
		})
	}

	t.Run("tampered payload", func(t *testing.T) {
		good := signed(t, hdr("RS256", "rsa-1"), claims, rsaSigner(rsaKey, crypto.SHA256, false))
		parts := strings.Split(good, ".")
		parts[1] = b64([]byte(`{"iss":"https://idp.example.com","aud":"attacker-app"}`))
		tok, err := Parse(strings.Join(parts, "."))
		if err != nil {
			t.Fatal(err)
		}
		if got := tok.Verify(keys); got.Status != Invalid {
			t.Errorf("Verify = %+v, want invalid", got)
		}
	})

	t.Run("key alg restriction", func(t *testing.T) {
		k := rsaJWK("rsa-1", &rsaKey.PublicKey)
		k["alg"] = "PS256"
		tok, _ := Parse(signed(t, hdr("RS256", "rsa-1"), claims, rsaSigner(rsaKey, crypto.SHA256, false)))
		if got := tok.Verify(jwks(t, k)); got.Status != Unchecked {
			t.Errorf("Verify = %+v, want unchecked: the key is only for PS256", got)
		}
	})
}

func TestParseJWKS(t *testing.T) {
	rsaKey := testutil.NewKeyPair(t, "idp.example.com").Key
	good := rsaJWK("rsa-1", &rsaKey.PublicKey)
	withD := rsaJWK("rsa-1", &rsaKey.PublicKey)
	withD["d"] = planted
	enc := rsaJWK("enc-1", &rsaKey.PublicKey)
	enc["use"] = "enc"
	// An odd modulus of exactly bits bits; parsing does not need a real key.
	modulus := func(bits int) string {
		n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		return b64(n.SetBit(n, 0, 1).Bytes())
	}
	atLimit := map[string]string{"kty": "RSA", "kid": "big-ok", "n": modulus(MaxRSABits), "e": "AQAB"}
	overLimit := map[string]string{"kty": "RSA", "kid": "too-big", "n": modulus(MaxRSABits + 1), "e": "AQAB"}
	offCurve := map[string]string{"kty": "EC", "crv": "P-256", "x": b64(make([]byte, 32)), "y": b64(append(make([]byte, 31), 1))}

	doc := func(keys ...map[string]string) string {
		b, _ := json.Marshal(map[string]any{"keys": keys})
		return string(b)
	}
	tests := []struct {
		name        string
		doc         string
		wantKeys    int
		wantSkipped int
		wantErr     string
	}{
		{name: "one key", doc: doc(good), wantKeys: 1},
		{name: "encryption key skipped", doc: doc(good, enc), wantKeys: 1, wantSkipped: 1},
		{name: "unknown kty skipped", doc: doc(good, map[string]string{"kty": "XYZ"}), wantKeys: 1, wantSkipped: 1},
		{name: "private key refused", doc: doc(withD), wantErr: "private or symmetric"},
		{name: "symmetric key refused", doc: doc(map[string]string{"kty": "oct", "k": planted}), wantErr: "private or symmetric"},
		{name: "only unusable keys", doc: doc(enc), wantErr: "no public signing keys"},
		{name: "bad modulus", doc: doc(map[string]string{"kty": "RSA", "n": "!!", "e": "AQAB"}), wantErr: `"n" is missing`},
		{name: "point not on curve", doc: doc(offCurve), wantErr: "not a valid point"},
		{name: "RSA key at the size limit", doc: doc(atLimit), wantKeys: 1},
		{name: "RSA key over the size limit", doc: doc(overLimit), wantErr: "over the 8192-bit limit"},
		{name: "not a key set", doc: `{"issuer":"x"}`, wantErr: `no "keys" array`},
		{name: "not JSON", doc: "<html>" + planted, wantErr: "not a JSON object"},
		{name: "too large", doc: strings.Repeat(" ", MaxJWKS+1), wantErr: "over the"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, err := ParseJWKS([]byte(tt.doc))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) || strings.Contains(err.Error(), planted) {
					t.Fatalf("error = %v, want containing %q and no document content", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseJWKS: %v", err)
			}
			if len(ks.Keys) != tt.wantKeys || ks.Skipped != tt.wantSkipped {
				t.Errorf("keys = %d, skipped = %d; want %d, %d", len(ks.Keys), ks.Skipped, tt.wantKeys, tt.wantSkipped)
			}
		})
	}
}

// TestVerifyTestutilJWT ties the fixture builder to the verifier, so rule
// tests that use testutil tokens can rely on them verifying.
func TestVerifyTestutilJWT(t *testing.T) {
	kp := testutil.NewKeyPair(t, "idp.example.com")
	ks, err := ParseJWKS(testutil.RSAJWKS(t, "lab-key-1", &kp.Key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Parse(testutil.SignJWT(t, kp.Key, "lab-key-1", map[string]any{"iss": "https://idp.example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := tok.Verify(ks); got.Status != Verified || got.KeyID != "lab-key-1" {
		t.Errorf("Verify = %+v", got)
	}
}
