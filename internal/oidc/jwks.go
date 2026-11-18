package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// MaxJWKS bounds a key set document. Real ones hold a handful of keys and
// are a few kilobytes.
const MaxJWKS = 1 << 20

// MaxRSABits bounds an RSA key's modulus. Verification time grows roughly
// with the square of the key size, so a hostile key set with one huge key
// could stall every signature check for seconds. Identity providers use
// 2048- to 4096-bit keys; 8192 leaves room without that cost.
const MaxRSABits = 8192

// Key is one public signing key from a JWK Set (RFC 7517).
type Key struct {
	ID  string // kid; tokens name the key that signed them with it
	Alg string // optional: the only algorithm this key may be used with
	pub crypto.PublicKey
}

// KeySet is the public keys the user trusts for verifying tokens.
type KeySet struct {
	Keys []Key
	// Skipped counts keys that were left out: encryption keys, and key
	// types or curves this package does not verify with.
	Skipped int
}

// jwk is one key as it appears on the wire. Only public members are read;
// d and k are listed so their presence can be refused.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"` // private part of an RSA, EC, or OKP key
	K   string `json:"k"` // a symmetric (shared secret) key
}

// ParseJWKS reads a JWK Set: {"keys": [...]}, as served at an IdP's
// jwks_uri.
//
// It refuses a document that contains private or symmetric key material:
// ssotrace never needs it, and the user may be about to share it. Errors
// never quote the document.
func ParseJWKS(data []byte) (*KeySet, error) {
	if len(data) > MaxJWKS {
		return nil, fmt.Errorf("key set is %d bytes, over the %d-byte limit", len(data), MaxJWKS)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := unmarshalObject(data, &doc); err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	if doc.Keys == nil {
		return nil, errors.New(`key set: no "keys" array; expected a JWK Set like an IdP's jwks_uri serves`)
	}

	ks := &KeySet{}
	for i, w := range doc.Keys {
		if w.D != "" || w.K != "" || strings.EqualFold(w.Kty, "oct") {
			return nil, fmt.Errorf("key set: key %d is private or symmetric key material; give only the IdP's public keys", i+1)
		}
		if w.Use == "enc" {
			ks.Skipped++ // encryption keys never sign tokens
			continue
		}
		pub, err := w.publicKey()
		if errors.Is(err, errUnsupportedKey) {
			ks.Skipped++
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("key set: key %d: %w", i+1, err)
		}
		ks.Keys = append(ks.Keys, Key{ID: w.Kid, Alg: w.Alg, pub: pub})
	}
	if len(ks.Keys) == 0 {
		return nil, errors.New("key set: no public signing keys this tool can use")
	}
	return ks, nil
}

var errUnsupportedKey = errors.New("unsupported key type")

func (w jwk) publicKey() (crypto.PublicKey, error) {
	switch w.Kty {
	case "RSA":
		n, err := bigInt(w.N, "n")
		if err != nil {
			return nil, err
		}
		if n.BitLen() > MaxRSABits {
			return nil, fmt.Errorf("RSA key is %d bits, over the %d-bit limit", n.BitLen(), MaxRSABits)
		}
		e, err := bigInt(w.E, "e")
		if err != nil {
			return nil, err
		}
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return nil, errors.New("RSA exponent is out of range")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		curve, size := ecCurve(w.Crv)
		if curve == nil {
			return nil, errUnsupportedKey
		}
		x, errX := fixedBytes(w.X, size, "x")
		y, errY := fixedBytes(w.Y, size, "y")
		if err := errors.Join(errX, errY); err != nil {
			return nil, err
		}
		// ParseUncompressedPublicKey also checks the point is on the
		// curve, which rejects invalid-curve keys.
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, errors.New("EC key is not a valid point on its curve")
		}
		return pub, nil
	case "OKP":
		if w.Crv != "Ed25519" {
			return nil, errUnsupportedKey
		}
		x, err := fixedBytes(w.X, ed25519.PublicKeySize, "x")
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, errUnsupportedKey
	}
}

func ecCurve(crv string) (elliptic.Curve, int) {
	switch crv {
	case "P-256":
		return elliptic.P256(), 32
	case "P-384":
		return elliptic.P384(), 48
	case "P-521":
		return elliptic.P521(), 66
	}
	return nil, 0
}

func bigInt(s, name string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("%q is missing or not base64url", name)
	}
	return new(big.Int).SetBytes(b), nil
}

func fixedBytes(s string, size int, name string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(b) != size {
		return nil, fmt.Errorf("%q is missing, not base64url, or the wrong length", name)
	}
	return b, nil
}

// VerifyStatus is the outcome of checking a token's signature.
type VerifyStatus string

// Outcomes. Unchecked is not a failure: it means ssotrace had nothing to
// check with, and rules report it as such rather than guessing.
const (
	Verified  VerifyStatus = "verified"  // a trusted key's signature matches
	Invalid   VerifyStatus = "invalid"   // a trusted key fits, but the signature does not match
	Unchecked VerifyStatus = "unchecked" // no usable key, or the algorithm cannot be checked here
)

// Verification is the result of Verify.
type Verification struct {
	Status VerifyStatus
	KeyID  string // the key that verified it, or the kid the token named
	Reason string // why it is Invalid or Unchecked; safe to display
}

// algorithm is how one JWA "alg" value is verified (RFC 7518 §3).
type algorithm struct {
	hash   crypto.Hash
	verify func(pub crypto.PublicKey, hash crypto.Hash, input, sig []byte) bool
}

var algorithms = map[string]algorithm{
	"RS256": {crypto.SHA256, verifyPKCS1}, "RS384": {crypto.SHA384, verifyPKCS1}, "RS512": {crypto.SHA512, verifyPKCS1},
	"PS256": {crypto.SHA256, verifyPSS}, "PS384": {crypto.SHA384, verifyPSS}, "PS512": {crypto.SHA512, verifyPSS},
	"ES256": {crypto.SHA256, verifyECDSA}, "ES384": {crypto.SHA384, verifyECDSA}, "ES512": {crypto.SHA512, verifyECDSA},
	"EdDSA": {0, verifyEd25519}, "Ed25519": {0, verifyEd25519},
}

// Verify checks the token's signature against the trusted keys in ks.
//
// The key decides the algorithm family, never the token alone: an RSA key
// only verifies RS/PS signatures, and shared-secret (HS) algorithms are
// never attempted. That closes the classic confusion attack in which a
// token claims HS256 so a verifier uses the RSA public key as the secret.
func (t *JWT) Verify(ks *KeySet) Verification {
	alg := t.Header.Alg
	switch {
	case ks == nil || len(ks.Keys) == 0:
		return Verification{Status: Unchecked, Reason: "no trusted keys were supplied"}
	case t.SignatureRedacted:
		return Verification{Status: Unchecked, Reason: "the signature was removed when the capture was redacted"}
	case !t.Signed() || strings.EqualFold(alg, "none"):
		return Verification{Status: Unchecked, Reason: "the token is unsigned"}
	case strings.HasPrefix(alg, "HS"):
		return Verification{Status: Unchecked, Reason: alg + " uses a shared secret, which only the client and the IdP hold"}
	}
	a, ok := algorithms[alg]
	if !ok {
		return Verification{Status: Unchecked, Reason: "algorithm " + alg + " is not supported"}
	}

	var candidates []Key
	for _, k := range ks.Keys {
		if (t.Header.Kid == "" || k.ID == t.Header.Kid) && (k.Alg == "" || k.Alg == alg) && keyFits(k.pub, alg) {
			candidates = append(candidates, k)
		}
	}
	if len(candidates) == 0 {
		reason := "no trusted key fits " + alg
		if t.Header.Kid != "" {
			reason = "no trusted " + alg + " key has kid " + t.Header.Kid
		}
		return Verification{Status: Unchecked, KeyID: t.Header.Kid, Reason: reason}
	}
	for _, k := range candidates {
		if a.verify(k.pub, a.hash, []byte(t.signingInput), t.signature) {
			return Verification{Status: Verified, KeyID: k.ID}
		}
	}
	return Verification{Status: Invalid, KeyID: t.Header.Kid, Reason: "the signature does not match the trusted key"}
}

// keyFits reports whether a key of this type, and for EC this curve, can
// produce alg signatures.
func keyFits(pub crypto.PublicKey, alg string) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")
	case *ecdsa.PublicKey:
		want := map[string]string{"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}[alg]
		return want != "" && k.Curve.Params().Name == want
	case ed25519.PublicKey:
		return alg == "EdDSA" || alg == "Ed25519"
	}
	return false
}

func digest(h crypto.Hash, input []byte) []byte {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(input)
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384(input)
		return d[:]
	default:
		d := sha512.Sum512(input)
		return d[:]
	}
}

func verifyPKCS1(pub crypto.PublicKey, h crypto.Hash, input, sig []byte) bool {
	return rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), h, digest(h, input), sig) == nil
}

// verifyPSS uses a salt as long as the hash, which RFC 7518 §3.5 requires.
func verifyPSS(pub crypto.PublicKey, h crypto.Hash, input, sig []byte) bool {
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
	return rsa.VerifyPSS(pub.(*rsa.PublicKey), h, digest(h, input), sig, opts) == nil
}

// verifyECDSA reads the JWS signature format: R and S as fixed-length
// big-endian integers, concatenated (RFC 7518 §3.4). This is not the ASN.1
// DER encoding most other ECDSA signatures use.
func verifyECDSA(pub crypto.PublicKey, h crypto.Hash, input, sig []byte) bool {
	k := pub.(*ecdsa.PublicKey)
	size := (k.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*size {
		return false
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	return ecdsa.Verify(k, digest(h, input), r, s)
}

func verifyEd25519(pub crypto.PublicKey, _ crypto.Hash, input, sig []byte) bool {
	return ed25519.Verify(pub.(ed25519.PublicKey), input, sig)
}
