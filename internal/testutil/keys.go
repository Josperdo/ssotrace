// Package testutil builds synthetic SSO fixtures for tests: throwaway keys,
// signed SAML messages, and HAR entries that carry them.
//
// Everything is generated at test time, so no private key, certificate, or
// captured traffic ever needs to be committed. Only _test.go files may import
// this package; the shipped binary never links it.
package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// RefTime is the fixed instant fixtures are built around. Tests that check
// time windows (NotBefore, NotOnOrAfter, certificate validity) compare
// against this instead of the wall clock, so they never flake.
var RefTime = time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

// KeyPair is a throwaway RSA key and the self-signed certificate for it,
// standing in for an IdP's (or SP's) signing credentials.
type KeyPair struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
}

// NewKeyPair generates a 2048-bit RSA key and a self-signed certificate
// valid for a year either side of RefTime.
//
// 2048 bits is the smallest size real IdPs use; anything smaller would make
// fixtures less realistic and some validators reject it outright.
func NewKeyPair(t testing.TB, commonName string) *KeyPair {
	t.Helper()
	return NewKeyPairValid(t, commonName, RefTime.AddDate(-1, 0, 0), RefTime.AddDate(1, 0, 0))
}

// NewKeyPairValid is NewKeyPair with chosen validity dates, for testing
// expired, not-yet-valid, and soon-to-expire certificates.
func NewKeyPairValid(t testing.TB, commonName string, notBefore, notAfter time.Time) *KeyPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"ssotrace synthetic test fixture"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	// Self-signed: the template is both subject and issuer.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return &KeyPair{Key: key, Cert: cert}
}
