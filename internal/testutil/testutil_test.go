package testutil

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/Josperdo/ssotrace/internal/flow"
	"github.com/Josperdo/ssotrace/internal/har"
)

// validate checks el's enveloped signature against trusted, at RefTime.
// It returns the element the validator vouches for, which is the only
// element signed-content checks may read (XML signature wrapping defense).
func validate(trusted *x509.Certificate, el *etree.Element) (*etree.Element, error) {
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{trusted},
	})
	ctx.Clock = dsig.NewFakeClockAt(RefTime)
	return ctx.Validate(el)
}

func parse(t *testing.T, xml []byte) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xml); err != nil {
		t.Fatalf("parse XML: %v", err)
	}
	return doc.Root()
}

func TestResponseSignatures(t *testing.T) {
	idp := NewKeyPair(t, "idp.example.com")
	other := NewKeyPair(t, "attacker.example.net")

	tests := []struct {
		name    string
		opts    func(*ResponseOptions)
		trusted *x509.Certificate
		tamper  func(root *etree.Element)
		target  string // "assertion" or "response": which signature to check
		wantOK  bool
	}{
		{name: "signed assertion verifies", target: "assertion", trusted: idp.Cert, wantOK: true},
		{
			name:    "signed response verifies",
			opts:    func(o *ResponseOptions) { o.SignAssertion, o.SignResponse = false, true },
			target:  "response",
			trusted: idp.Cert,
			wantOK:  true,
		},
		{
			name:    "both signed, outer verifies over signed inner",
			opts:    func(o *ResponseOptions) { o.SignResponse = true },
			target:  "response",
			trusted: idp.Cert,
			wantOK:  true,
		},
		{name: "wrong certificate", target: "assertion", trusted: other.Cert, wantOK: false},
		{
			name:    "tampered NameID",
			target:  "assertion",
			trusted: idp.Cert,
			tamper: func(root *etree.Element) {
				root.FindElement("./Assertion/Subject/NameID").SetText("mallory@example.com")
			},
			wantOK: false,
		},
		{
			name:    "unsigned assertion",
			opts:    func(o *ResponseOptions) { o.SignAssertion = false },
			target:  "assertion",
			trusted: idp.Cert,
			wantOK:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := DefaultResponseOptions()
			if tt.opts != nil {
				tt.opts(&o)
			}
			root := parse(t, Response(t, idp, o))
			if tt.tamper != nil {
				tt.tamper(root)
			}
			el := root
			if tt.target == "assertion" {
				el = root.FindElement("./Assertion")
			}

			got, err := validate(tt.trusted, el)
			if (err == nil) != tt.wantOK {
				t.Fatalf("validate error = %v, want ok = %v", err, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			// Read the NameID only from the validator's returned element.
			path := "./Subject/NameID"
			if tt.target == "response" {
				path = "./Assertion/Subject/NameID"
			}
			if n := got.FindElement(path); n == nil || n.Text() != "alice@example.com" {
				t.Errorf("NameID in validated element = %v", n)
			}
		})
	}
}

func TestResponseShape(t *testing.T) {
	idp := NewKeyPair(t, "idp.example.com")

	root := parse(t, Response(t, idp, DefaultResponseOptions()))
	a := root.FindElement("./Assertion")
	if a == nil {
		t.Fatal("success response has no Assertion")
	}
	// Schema order: Issuer, then Signature.
	if kids := a.ChildElements(); len(kids) < 2 || kids[0].Tag != "Issuer" || kids[1].Tag != "Signature" {
		t.Errorf("Assertion children do not start with Issuer, Signature")
	}

	o := DefaultResponseOptions()
	o.StatusCode = StatusRequester
	root = parse(t, Response(t, nil, o))
	if root.FindElement("./Assertion") != nil {
		t.Error("failed response contains an Assertion")
	}
	if v := root.FindElement("./Status/StatusCode").SelectAttrValue("Value", ""); v != StatusRequester {
		t.Errorf("StatusCode = %q", v)
	}
}

func TestRedirectURL(t *testing.T) {
	sp := NewKeyPair(t, "app.example.org")
	reqXML := AuthnRequest(t, DefaultAuthnRequestOptions())

	raw := RedirectURL(t, "https://idp.example.com/saml/sso", reqXML, "/home", sp)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()

	// The message round-trips through base64 + raw DEFLATE.
	compressed, err := base64.StdEncoding.DecodeString(q.Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(inflated, reqXML) {
		t.Error("inflated SAMLRequest differs from the original")
	}

	// The signature covers the query string up to (not including) Signature.
	sig, err := base64.StdEncoding.DecodeString(q.Get("Signature"))
	if err != nil {
		t.Fatal(err)
	}
	signed, _, _ := strings.Cut(u.RawQuery, "&Signature=")
	verify := func(s string) error {
		sum := sha256.Sum256([]byte(s))
		return rsa.VerifyPKCS1v15(&sp.Key.PublicKey, crypto.SHA256, sum[:], sig)
	}
	if err := verify(signed); err != nil {
		t.Errorf("redirect signature does not verify: %v", err)
	}
	if err := verify(strings.Replace(signed, "RelayState=%2Fhome", "RelayState=%2Fadmin", 1)); err == nil {
		t.Error("signature verified after RelayState was changed")
	}

	// Unsigned: no SigAlg or Signature parameters.
	if q := mustQuery(t, RedirectURL(t, "https://idp.example.com/saml/sso", reqXML, "", nil)); q.Has("Signature") || q.Has("SigAlg") {
		t.Error("unsigned redirect carries signature parameters")
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// TestSAMLLoginHAR is the end-to-end check: a generated login survives being
// written as a HAR file and read back by the real loader, and the signed
// assertion inside still verifies.
func TestSAMLLoginHAR(t *testing.T) {
	login := NewSAMLLogin(t, DefaultAuthnRequestOptions(), DefaultResponseOptions())

	h, err := har.Decode(bytes.NewReader(MarshalHAR(t, login.HAR)), har.DefaultMaxBytes)
	if err != nil {
		t.Fatalf("Decode generated HAR: %v", err)
	}
	if len(h.Log.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(h.Log.Entries))
	}
	for i := range h.Log.Entries {
		if p := flow.Detect(&h.Log.Entries[i]); p != flow.SAML {
			t.Errorf("entry %d detected as %v, want saml", i, p)
		}
	}

	post := &h.Log.Entries[1].Request
	b64, ok := post.FormParam("SAMLResponse")
	if !ok {
		t.Fatal("POST entry has no SAMLResponse")
	}
	xml, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("SAMLResponse base64: %v", err)
	}
	if !bytes.Equal(xml, login.ResponseXML) {
		t.Error("SAMLResponse from HAR differs from the generated one")
	}
	if _, err := validate(login.IDP.Cert, parse(t, xml).FindElement("./Assertion")); err != nil {
		t.Errorf("assertion from HAR does not verify: %v", err)
	}

	if v, _ := h.Log.Entries[0].Request.QueryParam("RelayState"); v != "/" {
		t.Errorf("RelayState = %q", v)
	}
}
