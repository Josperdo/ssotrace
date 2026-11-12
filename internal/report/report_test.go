package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Josperdo/ssotrace/internal/diagnose"
	"github.com/Josperdo/ssotrace/internal/flow"
	"github.com/Josperdo/ssotrace/internal/saml"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/golden")

// hostile is a value an attacker could plant in a HAR: a terminal escape
// that sets the window title, a right-to-left override, and a Markdown
// link. Every renderer must show it as inert text.
const hostile = "evil\x1b]0;pwned\x07\u202Etxt.exe [click](https://evil.example)"

func flowRef(i int) *int { return &i }

// sampleReport is a hand-built report covering every layout case: a
// capture-wide warning and note, a flow with a failure and a warning, an
// IdP-initiated flow, a flow with no response, and a clean flow. It is
// written by hand, not generated from signed fixtures, so the golden files
// are byte-for-byte stable (real signatures use a fresh key every run).
func sampleReport() *Report {
	msg := func(entry int, method, url, at string) *flow.SAMLMessage {
		return &flow.SAMLMessage{Entry: entry, Method: method, URL: url, Time: at}
	}
	req := func(entry int, at string) *flow.SAMLMessage {
		m := msg(entry, "GET", "https://idp.example.com/saml/sso", at)
		m.Message = &saml.Message{Kind: saml.KindAuthnRequest, AuthnRequest: &saml.AuthnRequest{ACSURL: "https://app.example.org/saml/acs"}}
		return m
	}
	resp := func(entry int, at string) *flow.SAMLMessage {
		return msg(entry, "POST", "https://app.example.org/saml/acs", at)
	}
	trace := &flow.SAMLTrace{Flows: []flow.SAMLFlow{
		{Request: req(1, "2026-01-15T10:00:00Z"), Response: resp(3, "2026-01-15T10:00:01Z")},
		{Response: resp(5, "2026-01-15T10:01:00Z"), IDPInitiated: true},
		{Request: req(7, "2026-01-15T10:02:00Z")},
		{Request: req(9, "2026-01-15T10:03:00Z"), Response: resp(11, "2026-01-15T10:03:01Z")},
	}}

	return &Report{
		File:    "login.har",
		Version: "v0.0.0-test",
		SAML:    trace,
		Findings: []diagnose.Finding{
			{RuleID: "HAR001", Severity: diagnose.Pass, Title: "SSO traffic found"},
			{RuleID: "HAR004", Severity: diagnose.Warn, Title: "IdP error code found",
				Detail:   "The capture contains 1 error code from the identity provider.",
				Fix:      "Look up the code in the identity provider's documentation.",
				Evidence: []diagnose.Evidence{{Label: "AADSTS50011", Value: "Microsoft Entra ID, entry 4: GET https://login.example.com/cb (URL)"}}},
			{RuleID: "SAML001", Severity: diagnose.Pass, Title: "IdP reported success"},
			{RuleID: "SAML002", Flow: flowRef(0), Severity: diagnose.Fail, Title: "Assertion audience does not match the SP",
				Detail: "The IdP addressed this assertion to a different SP (Audience) than the one that requested the login. The SP will reject it.",
				Fix:    "In the IdP's settings for this application, set the Audience to exactly the SP entity ID in the evidence. Watch for http vs https, trailing slashes, and an old or staging value.",
				Evidence: []diagnose.Evidence{
					{Label: "Response", Value: "entry 3: POST https://app.example.org/saml/acs"},
					{Label: "Assertion audience", Value: hostile},
					{Label: "SP entity ID", Value: "https://app.example.org/saml/metadata"},
				}},
			{RuleID: "SAML005", Flow: flowRef(1), Severity: diagnose.Info, Title: "IdP-initiated login",
				Fix: "If the SP rejects it, allow IdP-initiated SSO in the SP or start the login from the application."},
			{RuleID: "SAML005", Flow: flowRef(2), Severity: diagnose.Fail, Title: "IdP rejected the login request",
				Detail:   "The IdP answered the SP's AuthnRequest with an HTTP error and never sent a Response back.",
				Fix:      "Check the IdP's logs at this time.",
				Evidence: []diagnose.Evidence{{Label: "AuthnRequest", Value: "entry 7: GET https://idp.example.com/saml/sso"}, {Label: "IdP HTTP status", Value: "400"}}},
			{RuleID: "SAML010", Flow: flowRef(0), Severity: diagnose.Warn, Title: "Response uses a weak signature algorithm",
				Fix:      "Change the signature algorithm to RSA-SHA256.",
				Evidence: []diagnose.Evidence{{Label: "Signature algorithm", Value: "RSA-SHA1"}}},
			{RuleID: "SAML013", Severity: diagnose.Info, Title: "Signer not checked against a trusted certificate",
				Fix: "To check who signed, run again with --idp-cert."},
		},
	}
}

// golden compares got with testdata/golden/name, or rewrites the file
// when the test runs with -update. Review the diff before committing: a
// golden change is a user-visible output change.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "golden", name)
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden file (run with -update to create it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden file; run `make golden` and review the diff.\n--- got ---\n%s", name, got)
	}
}

func TestGolden(t *testing.T) {
	tests := []struct {
		file   string
		render func(*bytes.Buffer, *Report) error
	}{
		{"diagnose.txt", func(b *bytes.Buffer, r *Report) error { return Text(b, r, TextOptions{}) }},
		{"diagnose.color.txt", func(b *bytes.Buffer, r *Report) error { return Text(b, r, TextOptions{Color: true}) }},
		{"diagnose.md", func(b *bytes.Buffer, r *Report) error { return Markdown(b, r) }},
		{"diagnose.json", func(b *bytes.Buffer, r *Report) error { return JSON(b, r) }},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tt.render(&buf, sampleReport()); err != nil {
				t.Fatal(err)
			}
			golden(t, tt.file, buf.Bytes())
		})
	}
}

// TestHostileValuesAreInert checks the security properties directly, so
// they cannot be lost by carelessly accepting a golden-file update.
func TestHostileValuesAreInert(t *testing.T) {
	r := sampleReport()

	var text bytes.Buffer
	if err := Text(&text, r, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"\x1b", "\x07", "\u202E"} {
		if strings.Contains(text.String(), bad) {
			t.Errorf("text output contains %q from the capture", bad)
		}
	}

	var md bytes.Buffer
	if err := Markdown(&md, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(md.String(), "](https://evil.example)") && !strings.Contains(md.String(), "`evil") {
		t.Error("markdown output turned a planted link into a real link")
	}
	if strings.ContainsAny(md.String(), "\x1b\x07\u202E") {
		t.Error("markdown output contains control or bidi characters from the capture")
	}

	var js bytes.Buffer
	if err := JSON(&js, r); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(js.String(), "\x1b\x07") {
		t.Error("json output contains raw control characters")
	}
	var back struct {
		SchemaVersion int    `json:"schema_version"`
		Summary       Counts `json:"summary"`
	}
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || back.SchemaVersion != 1 || back.Summary.Fail != 2 {
		t.Errorf("json = %+v, err %v", back, err)
	}
}

func TestMarkdownCode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain", "`plain`"},
		{"has `tick`", "`` has `tick` ``"},
		{"a|b", "`a\\|b`"},
		{"`edge", "`` `edge ``"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := mdCode(tt.in); got != tt.want {
			t.Errorf("mdCode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestWrap(t *testing.T) {
	got := wrap("one two three four https://a-very-long-url.example.com/that/does/not/fit", 12)
	want := []string{"one two", "three four", "https://a-very-long-url.example.com/that/does/not/fit"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("wrap = %q, want %q", got, want)
	}
}

// TestEmptyReport: no SAML and no findings still renders, without panics.
func TestEmptyReport(t *testing.T) {
	r := &Report{File: "empty.har"}
	var b bytes.Buffer
	if err := Text(&b, r, TextOptions{}); err != nil || !strings.Contains(b.String(), "no SAML logins found") {
		t.Errorf("text = %q, err %v", b.String(), err)
	}
	b.Reset()
	if err := Markdown(&b, r); err != nil {
		t.Error(err)
	}
	b.Reset()
	if err := JSON(&b, r); err != nil || !strings.Contains(b.String(), `"findings": []`) {
		t.Errorf("json = %q, err %v", b.String(), err)
	}
}
