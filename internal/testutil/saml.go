package testutil

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAML 2.0 namespaces and URIs used in fixtures.
const (
	NSProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	NSAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"

	StatusSuccess   = "urn:oasis:names:tc:SAML:2.0:status:Success"
	StatusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester"

	BindingPOST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	NameIDEmail      = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDPersistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

	// SigAlgRSASHA256 is the SigAlg value for HTTP-Redirect signatures.
	SigAlgRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

	cmBearerURI = "urn:oasis:names:tc:SAML:2.0:cm:bearer" //nolint:gosec // public SAML spec URI, not a credential
	authnClass  = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
)

// samlTime is the xs:dateTime form SAML uses: UTC with a "Z" suffix.
const samlTime = "2006-01-02T15:04:05Z"

// ResponseOptions describes a SAML Response. Start from
// DefaultResponseOptions and change only the field a test cares about, so
// each test reads as "a normal response, except ...".
type ResponseOptions struct {
	ID            string
	AssertionID   string
	InResponseTo  string
	IssueInstant  time.Time
	Issuer        string // IdP entity ID
	Destination   string // SP's ACS URL the IdP addressed the Response to
	Recipient     string // where the bearer assertion may be delivered
	Audience      string // SP entity ID the assertion is meant for
	NameID        string
	NotBefore     time.Time
	NotOnOrAfter  time.Time
	StatusCode    string // a non-success status produces no assertion
	StatusSubCode string // optional second-level status code
	StatusMessage string // optional human-readable status message
	NameIDFormat  string

	SignAssertion bool
	SignResponse  bool
	// SHA1 signs with RSA-SHA1 and a SHA-1 digest, as old IdPs still do.
	SHA1 bool
	// Encrypt replaces the Assertion with an EncryptedAssertion
	// placeholder. It is not real encryption: ssotrace never decrypts, so
	// only the element's presence matters to tests.
	Encrypt bool
}

// DefaultResponseOptions returns a successful, assertion-signed response
// from a synthetic IdP to a synthetic SP, issued at RefTime.
func DefaultResponseOptions() ResponseOptions {
	return ResponseOptions{
		ID:            "_00000000-0000-0000-0000-000000000002",
		AssertionID:   "_00000000-0000-0000-0000-000000000003",
		InResponseTo:  "_00000000-0000-0000-0000-000000000001",
		IssueInstant:  RefTime,
		Issuer:        "https://idp.example.com/saml",
		Destination:   "https://app.example.org/saml/acs",
		Recipient:     "https://app.example.org/saml/acs",
		Audience:      "https://app.example.org/saml/metadata",
		NameID:        "alice@example.com",
		NameIDFormat:  NameIDEmail,
		NotBefore:     RefTime.Add(-1 * time.Minute),
		NotOnOrAfter:  RefTime.Add(5 * time.Minute),
		StatusCode:    StatusSuccess,
		SignAssertion: true,
	}
}

// Response builds a SAML Response and returns its XML. kp signs it when
// SignAssertion or SignResponse is set; it may be nil otherwise.
func Response(t testing.TB, kp *KeyPair, o ResponseOptions) []byte {
	t.Helper()

	resp := etree.NewElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", NSProtocol)
	resp.CreateAttr("xmlns:saml", NSAssertion)
	resp.CreateAttr("ID", o.ID)
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", o.IssueInstant.UTC().Format(samlTime))
	resp.CreateAttr("Destination", o.Destination)
	if o.InResponseTo != "" {
		resp.CreateAttr("InResponseTo", o.InResponseTo)
	}
	resp.CreateElement("saml:Issuer").SetText(o.Issuer)
	status := resp.CreateElement("samlp:Status")
	code := status.CreateElement("samlp:StatusCode")
	code.CreateAttr("Value", o.StatusCode)
	if o.StatusSubCode != "" {
		code.CreateElement("samlp:StatusCode").CreateAttr("Value", o.StatusSubCode)
	}
	if o.StatusMessage != "" {
		status.CreateElement("samlp:StatusMessage").SetText(o.StatusMessage)
	}

	// An IdP that refuses a login sends a Status and nothing else.
	switch {
	case o.StatusCode != StatusSuccess:
	case o.Encrypt:
		enc := resp.CreateElement("saml:EncryptedAssertion")
		enc.CreateElement("xenc:EncryptedData").CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	default:
		a := assertion(o)
		if o.SignAssertion {
			a = sign(t, kp, a, o.SHA1)
		}
		resp.AddChild(a)
	}
	if o.SignResponse {
		resp = sign(t, kp, resp, o.SHA1)
	}

	doc := etree.NewDocument()
	doc.SetRoot(resp)
	out, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize Response: %v", err)
	}
	return out
}

// assertion builds the Assertion element. It declares the saml namespace
// itself, so it stays well-formed when signed on its own and then embedded.
func assertion(o ResponseOptions) *etree.Element {
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", NSAssertion)
	a.CreateAttr("ID", o.AssertionID)
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", o.IssueInstant.UTC().Format(samlTime))
	a.CreateElement("saml:Issuer").SetText(o.Issuer)

	subj := a.CreateElement("saml:Subject")
	nameID := subj.CreateElement("saml:NameID")
	if o.NameIDFormat != "" {
		nameID.CreateAttr("Format", o.NameIDFormat)
	}
	nameID.SetText(o.NameID)
	conf := subj.CreateElement("saml:SubjectConfirmation")
	conf.CreateAttr("Method", cmBearerURI)
	data := conf.CreateElement("saml:SubjectConfirmationData")
	if o.InResponseTo != "" {
		data.CreateAttr("InResponseTo", o.InResponseTo)
	}
	data.CreateAttr("NotOnOrAfter", o.NotOnOrAfter.UTC().Format(samlTime))
	data.CreateAttr("Recipient", o.Recipient)

	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", o.NotBefore.UTC().Format(samlTime))
	cond.CreateAttr("NotOnOrAfter", o.NotOnOrAfter.UTC().Format(samlTime))
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(o.Audience)

	stmt := a.CreateElement("saml:AuthnStatement")
	stmt.CreateAttr("AuthnInstant", o.IssueInstant.UTC().Format(samlTime))
	stmt.CreateAttr("SessionIndex", "_00000000-0000-0000-0000-000000000004")
	stmt.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText(authnClass)
	return a
}

// sign returns el with an enveloped XML signature inserted.
//
// The SAML schema requires the Signature to come right after Issuer, so it is
// inserted at index 1 rather than appended. Position does not change the
// digest: the enveloped-signature transform removes the Signature before
// hashing, wherever it sits.
func sign(t testing.TB, kp *KeyPair, el *etree.Element, sha1 bool) *etree.Element {
	t.Helper()
	if kp == nil {
		t.Fatal("signing requested but no KeyPair given")
	}
	ctx, err := dsig.NewSigningContext(kp.Key, [][]byte{kp.Cert.Raw})
	if err != nil {
		t.Fatalf("signing context: %v", err)
	}
	// Exclusive canonicalization is what SAML IdPs use: it ignores namespace
	// declarations inherited from ancestors, so a signed Assertion still
	// verifies after being moved into a different Response.
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if sha1 {
		ctx.Hash = crypto.SHA1
	}
	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		t.Fatalf("sign %s: %v", el.Tag, err)
	}
	out := el.Copy()
	out.InsertChildAt(1, sig)
	return out
}

// AuthnRequestOptions describes an SP's AuthnRequest.
type AuthnRequestOptions struct {
	ID           string
	IssueInstant time.Time
	Issuer       string // SP entity ID
	Destination  string // IdP SSO URL
	ACSURL       string
	NameIDFormat string // NameIDPolicy Format; "" omits NameIDPolicy
}

// DefaultAuthnRequestOptions matches DefaultResponseOptions: its ID is the
// default InResponseTo, and its URLs are the same SP and IdP.
func DefaultAuthnRequestOptions() AuthnRequestOptions {
	return AuthnRequestOptions{
		ID:           "_00000000-0000-0000-0000-000000000001",
		IssueInstant: RefTime.Add(-5 * time.Second),
		Issuer:       "https://app.example.org/saml/metadata",
		Destination:  "https://idp.example.com/saml/sso",
		ACSURL:       "https://app.example.org/saml/acs",
	}
}

// AuthnRequest builds an AuthnRequest and returns its XML.
func AuthnRequest(t testing.TB, o AuthnRequestOptions) []byte {
	t.Helper()
	req := etree.NewElement("samlp:AuthnRequest")
	req.CreateAttr("xmlns:samlp", NSProtocol)
	req.CreateAttr("xmlns:saml", NSAssertion)
	req.CreateAttr("ID", o.ID)
	req.CreateAttr("Version", "2.0")
	req.CreateAttr("IssueInstant", o.IssueInstant.UTC().Format(samlTime))
	req.CreateAttr("Destination", o.Destination)
	req.CreateAttr("AssertionConsumerServiceURL", o.ACSURL)
	req.CreateAttr("ProtocolBinding", BindingPOST)
	req.CreateElement("saml:Issuer").SetText(o.Issuer)
	if o.NameIDFormat != "" {
		p := req.CreateElement("samlp:NameIDPolicy")
		p.CreateAttr("Format", o.NameIDFormat)
		p.CreateAttr("AllowCreate", "true")
	}

	doc := etree.NewDocument()
	doc.SetRoot(req)
	out, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize AuthnRequest: %v", err)
	}
	return out
}

// RedirectURL encodes msg for the HTTP-Redirect binding and returns the full
// URL to send the browser to. If kp is non-nil the URL is signed.
//
// Redirect signatures are not XML signatures: a URL has no room for one.
// Instead the signer hashes the exact query string
// "SAMLRequest=...&RelayState=...&SigAlg=..." (in that order, values
// URL-encoded) and appends the result as a Signature parameter.
func RedirectURL(t testing.TB, base string, msg []byte, relayState string, kp *KeyPair) string {
	t.Helper()
	q := "SAMLRequest=" + url.QueryEscape(deflateBase64(t, msg))
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	if kp != nil {
		q += "&SigAlg=" + url.QueryEscape(SigAlgRSASHA256)
		sum := sha256.Sum256([]byte(q))
		sig, err := rsa.SignPKCS1v15(rand.Reader, kp.Key, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatalf("sign redirect: %v", err)
		}
		q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	return base + "?" + q
}

// deflateBase64 is the HTTP-Redirect message encoding: raw DEFLATE with no
// zlib header, then standard base64.
func deflateBase64(t testing.TB, msg []byte) string {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}
	if _, err := fw.Write(msg); err != nil {
		t.Fatalf("deflate: %v", err)
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("deflate: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}
