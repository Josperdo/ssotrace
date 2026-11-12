package saml

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// TrustEmbedded marks a signature checked only against the certificate the
// message itself carries.
const TrustEmbedded = "embedded-certificate"

// verify checks el's own enveloped signature.
//
// It returns the signature description and, only if the signature
// verified, the element the validator vouches for. Callers must read signed
// content from that returned element and never from el: that is the whole
// defense against XML signature wrapping, where an attacker leaves the
// signed element intact and adds a second, unsigned one for the reader to
// find instead.
//
// at is the reference time for certificate validity: the HAR timestamp of
// the message, not the wall clock, so results do not change with the date
// the capture is analyzed.
func verify(el *etree.Element, at time.Time) (Signature, *etree.Element) {
	sigEl := child(el, nsDSig, "Signature")
	if sigEl == nil {
		return Signature{}, nil
	}
	sig := Signature{
		Present:         true,
		TrustedBy:       TrustEmbedded,
		Algorithm:       attr(sigEl.FindElement("./SignedInfo/SignatureMethod"), "Algorithm"),
		DigestAlgorithm: attr(sigEl.FindElement("./SignedInfo/Reference/DigestMethod"), "Algorithm"),
	}

	cert, err := embeddedCert(sigEl)
	if err != nil {
		sig.Error = err.Error()
		return sig, nil
	}
	sig.Certificate = describeCert(cert)
	sig.Certificate.ValidityAtCapture = validityAt(cert, at)

	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})
	// goxmldsig rejects a certificate outside its validity dates before it
	// checks the cryptography, so an expired certificate would hide whether
	// the signature itself is good. Expiry is recorded above and judged by
	// its own rule; the cryptographic check runs at a moment the
	// certificate is valid, so it answers only "was this altered?".
	checkAt := at
	if sig.Certificate.ValidityAtCapture != ValidityValid {
		checkAt = cert.NotBefore
	}
	ctx.Clock = dsig.NewFakeClockAt(checkAt)
	validated, err := ctx.Validate(el)
	if err != nil {
		sig.Error = safeSigError(err)
		return sig, nil
	}
	sig.Verified = true
	return sig, validated
}

// embeddedCert extracts the signer's certificate from KeyInfo.
func embeddedCert(sigEl *etree.Element) (*x509.Certificate, error) {
	certEl := sigEl.FindElement("./KeyInfo/X509Data/X509Certificate")
	if certEl == nil {
		return nil, errors.New("signature carries no X509Certificate")
	}
	der, err := decodeBase64(text(certEl))
	if err != nil {
		return nil, errors.New("embedded certificate is not valid base64")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("embedded certificate could not be parsed")
	}
	return cert, nil
}

func describeCert(c *x509.Certificate) *Certificate {
	sum := sha256.Sum256(c.Raw)
	return &Certificate{
		Subject:      c.Subject.String(),
		Issuer:       c.Issuer.String(),
		NotBefore:    c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:     c.NotAfter.UTC().Format(time.RFC3339),
		SHA256:       strings.ToUpper(hex.EncodeToString(sum[:])),
		SelfSigned:   bytes.Equal(c.RawSubject, c.RawIssuer),
		PublicKeyAlg: c.PublicKeyAlgorithm.String(),
	}
}

func validityAt(c *x509.Certificate, at time.Time) string {
	switch {
	case at.IsZero():
		return ValidityUnknown
	case at.Before(c.NotBefore):
		return ValidityNotYetValid
	case at.After(c.NotAfter):
		return ValidityExpired
	default:
		return ValidityValid
	}
}

// safeSigError turns a validator error into text safe to display.
//
// Some goxmldsig messages append a value read from the document, such as
// "Unknown Transform Algorithm: <whatever the file says>". A hostile file
// could plant a secret there, so everything after the first colon is
// dropped. The fixed prefix still says what went wrong.
func safeSigError(err error) string {
	msg, _, _ := strings.Cut(err.Error(), ":")
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return "signature could not be validated"
	}
	return strings.ToLower(msg[:1]) + msg[1:]
}
