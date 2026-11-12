package saml

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Josperdo/ssotrace/internal/testutil"
)

func TestCheckXMLLimits(t *testing.T) {
	deep := func(n int) string {
		return strings.Repeat("<a>", n) + strings.Repeat("</a>", n)
	}
	tests := []struct {
		name    string
		input   string
		wantErr string // "" means accepted
	}{
		{"at max depth", deep(MaxDepth), ""},
		{"too deep", deep(MaxDepth + 1), "nesting deeper"},
		{"doctype", `<!DOCTYPE r [<!ENTITY x "` + plantedSecret + `">]><r>&x;</r>`, "DOCTYPE"},
		{"malformed", `<a><b>` + plantedSecret + `</a>`, "malformed"},
		{"truncated", `<a><b>`, "truncated"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseXML([]byte(tt.input))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("parseXML: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), plantedSecret) {
				t.Errorf("error %q leaks input", err)
			}
		})
	}
}

func TestParseAuthnRequest(t *testing.T) {
	o := testutil.DefaultAuthnRequestOptions()
	m, err := Parse(testutil.AuthnRequest(t, o), testutil.RefTime)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Kind != KindAuthnRequest || m.AuthnRequest == nil {
		t.Fatalf("kind = %v", m.Kind)
	}
	r := m.AuthnRequest
	checks := map[string][2]string{
		"ID":          {r.ID, o.ID},
		"Issuer":      {r.Issuer, o.Issuer},
		"Destination": {r.Destination, o.Destination},
		"ACSURL":      {r.ACSURL, o.ACSURL},
		"Binding":     {r.ProtocolBinding, testutil.BindingPOST},
		"Instant":     {r.IssueInstant, "2026-01-15T09:59:55Z"},
	}
	for field, gw := range checks {
		if gw[0] != gw[1] {
			t.Errorf("%s = %q, want %q", field, gw[0], gw[1])
		}
	}
	if r.Signature.Present {
		t.Error("unsigned request reports a signature")
	}
}

func TestParseResponse(t *testing.T) {
	idp := testutil.NewKeyPair(t, "idp.example.com")
	o := testutil.DefaultResponseOptions()

	m, err := Parse(testutil.Response(t, idp, o), testutil.RefTime)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := m.Response
	if r == nil || m.Kind != KindResponse {
		t.Fatalf("kind = %v", m.Kind)
	}
	if r.ID != o.ID || r.InResponseTo != o.InResponseTo || r.Destination != o.Destination || r.Issuer != o.Issuer {
		t.Errorf("response header = %+v", r)
	}
	if r.Status.Code != testutil.StatusSuccess {
		t.Errorf("status = %+v", r.Status)
	}
	if r.Signature.Present {
		t.Error("response-level signature reported, but only the assertion is signed")
	}
	if len(r.Assertions) != 1 {
		t.Fatalf("assertions = %d", len(r.Assertions))
	}

	a := r.Assertions[0]
	if !a.Verified || !a.Signature.Verified || a.Signature.TrustedBy != TrustEmbedded {
		t.Errorf("assertion signature = %+v, verified = %v", a.Signature, a.Verified)
	}
	if c := a.Signature.Certificate; c == nil || !strings.Contains(c.Subject, "CN=idp.example.com") || !c.SelfSigned || len(c.SHA256) != 64 {
		t.Errorf("certificate = %+v", c)
	}
	if a.Subject.NameID.Value != o.NameID {
		t.Errorf("NameID = %q", a.Subject.NameID.Value)
	}
	if a.Conditions == nil || len(a.Conditions.Audiences) != 1 || a.Conditions.Audiences[0] != o.Audience {
		t.Errorf("conditions = %+v", a.Conditions)
	}
	if a.Conditions.NotOnOrAfter != "2026-01-15T10:05:00Z" {
		t.Errorf("NotOnOrAfter = %q", a.Conditions.NotOnOrAfter)
	}
	if len(a.Subject.Confirmations) != 1 || a.Subject.Confirmations[0].Recipient != o.Destination {
		t.Errorf("confirmations = %+v", a.Subject.Confirmations)
	}
	if len(a.AuthnStmts) != 1 || a.AuthnStmts[0].SessionIndexPreview == "" ||
		strings.Contains(a.AuthnStmts[0].SessionIndexPreview, "0000-0000-0000-000000000004") {
		t.Errorf("authn statement = %+v (SessionIndex must be previewed, not shown)", a.AuthnStmts)
	}
}

func TestParseResponseSignatureStates(t *testing.T) {
	idp := testutil.NewKeyPair(t, "idp.example.com")

	tests := []struct {
		name         string
		opts         func(*testutil.ResponseOptions)
		mutate       func([]byte) []byte
		wantRespSig  bool
		wantVerified bool
		wantErr      string
	}{
		{name: "assertion signed", wantVerified: true},
		{
			name:         "only response signed covers assertion",
			opts:         func(o *testutil.ResponseOptions) { o.SignAssertion, o.SignResponse = false, true },
			wantRespSig:  true,
			wantVerified: true,
		},
		{
			name:         "unsigned",
			opts:         func(o *testutil.ResponseOptions) { o.SignAssertion = false },
			wantVerified: false,
		},
		{
			name: "tampered after signing",
			mutate: func(b []byte) []byte {
				return bytes.Replace(b, []byte("alice@example.com"), []byte("mallory@example.com"), 1)
			},
			wantVerified: false,
			wantErr:      "signature could not be verified",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := testutil.DefaultResponseOptions()
			if tt.opts != nil {
				tt.opts(&o)
			}
			raw := testutil.Response(t, idp, o)
			if tt.mutate != nil {
				raw = tt.mutate(raw)
			}
			m, err := Parse(raw, testutil.RefTime)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			r := m.Response
			if r.Signature.Present != tt.wantRespSig {
				t.Errorf("response signature present = %v", r.Signature.Present)
			}
			a := r.Assertions[0]
			if a.Verified != tt.wantVerified {
				t.Errorf("assertion verified = %v, want %v (sig %+v)", a.Verified, tt.wantVerified, a.Signature)
			}
			if tt.wantErr != "" && !strings.Contains(a.Signature.Error, tt.wantErr) {
				t.Errorf("signature error = %q, want %q", a.Signature.Error, tt.wantErr)
			}
		})
	}
}

// TestParseExpiredCertificate: certificate validity is judged at the
// message's own time, so the same bytes verify at RefTime and fail years
// later, deterministically.
func TestParseExpiredCertificate(t *testing.T) {
	idp := testutil.NewKeyPair(t, "idp.example.com")
	raw := testutil.Response(t, idp, testutil.DefaultResponseOptions())

	m, err := Parse(raw, testutil.RefTime.AddDate(3, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	sig := m.Response.Assertions[0].Signature
	if sig.Verified || !strings.Contains(sig.Error, "not valid at this time") {
		t.Errorf("signature = %+v", sig)
	}
}

// TestCommentInjection reproduces the 2018 NameID comment attack: the IdP
// signs "alice@example.com.evil.example", an attacker inserts a comment,
// and the signature still verifies because canonicalization drops
// comments. A reader that stops at the comment would see
// "alice@example.com".
func TestCommentInjection(t *testing.T) {
	idp := testutil.NewKeyPair(t, "idp.example.com")
	o := testutil.DefaultResponseOptions()
	o.NameID = "alice@example.com.evil.example"
	raw := bytes.Replace(testutil.Response(t, idp, o),
		[]byte("alice@example.com.evil.example"),
		[]byte("alice@example.com<!---->.evil.example"), 1)

	m, err := Parse(raw, testutil.RefTime)
	if err != nil {
		t.Fatal(err)
	}
	a := m.Response.Assertions[0]
	if !a.Verified {
		t.Fatalf("comment should not break the signature: %+v", a.Signature)
	}
	if got := a.Subject.NameID.Value; got != "alice@example.com.evil.example" {
		t.Errorf("NameID = %q, want the full signed value", got)
	}
}

// TestSignatureWrapping inserts an unsigned, attacker-written Assertion in
// front of the genuine signed one. Whatever reads the model must be able to
// tell them apart: only the genuine one is Verified.
func TestSignatureWrapping(t *testing.T) {
	idp := testutil.NewKeyPair(t, "idp.example.com")
	raw := testutil.Response(t, idp, testutil.DefaultResponseOptions())

	evil := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_evil" Version="2.0" IssueInstant="2026-01-15T10:00:00Z">` +
		`<saml:Issuer>https://idp.example.com/saml</saml:Issuer>` +
		`<saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject></saml:Assertion>`
	i := bytes.Index(raw, []byte("<saml:Assertion"))
	wrapped := append(append(append([]byte{}, raw[:i]...), evil...), raw[i:]...)

	m, err := Parse(wrapped, testutil.RefTime)
	if err != nil {
		t.Fatal(err)
	}
	as := m.Response.Assertions
	if len(as) != 2 {
		t.Fatalf("assertions = %d", len(as))
	}
	if as[0].Verified || as[0].Subject.NameID.Value != "admin@example.com" {
		t.Errorf("injected assertion = verified %v, NameID %q", as[0].Verified, as[0].Subject.NameID.Value)
	}
	if !as[1].Verified || as[1].Subject.NameID.Value != "alice@example.com" {
		t.Errorf("genuine assertion = verified %v, NameID %q", as[1].Verified, as[1].Subject.NameID.Value)
	}
}

func TestParseStatusAndKinds(t *testing.T) {
	const failed = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0" IssueInstant="2026-01-15T10:00:00Z">` +
		`<saml:Issuer>https://idp.example.com/saml</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">` +
		`<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/></samlp:StatusCode>` +
		`<samlp:StatusMessage>Invalid user</samlp:StatusMessage></samlp:Status>` +
		`<saml:EncryptedAssertion/></samlp:Response>`
	m, err := Parse([]byte(failed), testutil.RefTime)
	if err != nil {
		t.Fatal(err)
	}
	s := m.Response.Status
	if !strings.HasSuffix(s.Code, ":Responder") || !strings.HasSuffix(s.SubCode, ":AuthnFailed") || s.Message != "Invalid user" {
		t.Errorf("status = %+v", s)
	}
	if m.Response.EncryptedAssertions != 1 || len(m.Response.Assertions) != 0 {
		t.Errorf("encrypted = %d, assertions = %d", m.Response.EncryptedAssertions, len(m.Response.Assertions))
	}

	// A different prefix for the same namespace is the same element.
	if m, err := Parse([]byte(`<p:LogoutRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"/>`), testutil.RefTime); err != nil || m.Kind != KindLogoutRequest {
		t.Errorf("logout: kind %v, err %v", m.Kind, err)
	}
	// The right local name in the wrong namespace is not SAML.
	if _, err := Parse([]byte(`<samlp:Response xmlns:samlp="urn:example:not-saml"/>`), testutil.RefTime); err == nil {
		t.Error("wrong namespace accepted")
	}
}
