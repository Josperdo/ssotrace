package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Josperdo/ssotrace/internal/har"
	"github.com/Josperdo/ssotrace/internal/saml"
	"github.com/Josperdo/ssotrace/internal/testutil"
)

var testSalt = []byte("fixed-test-salt-not-a-secret-0000")

// richHAR builds a capture with one of everything the redactor handles: a
// signed SAML login, session cookies, a bearer token, an OAuth callback
// with a code, an implicit-flow id_token in the fragment, a password form,
// a token endpoint response, and an IdP error page.
func richHAR(t *testing.T) *har.HAR {
	t.Helper()
	login := testutil.NewSAMLLogin(t, testutil.DefaultAuthnRequestOptions(), testutil.DefaultResponseOptions())

	at := testutil.RefTime.Add(time.Minute)
	home := testutil.GetEntry(t, "https://app.example.com/home", at, 200)
	home.Request.Cookies = []har.Cookie{{Name: "session", Value: fakeCookie, Path: "/", Secure: true, HTTPOnly: true}}
	home.Request.Headers = []har.NameValue{
		{Name: "Cookie", Value: "session=" + fakeCookie + "; theme=dark"},
		{Name: "Authorization", Value: fakeBearer},
		{Name: "User-Agent", Value: "Mozilla/5.0 (synthetic)"},
		{Name: "X-Request-Id", Value: "req-0123456789"},
	}
	home.Response.Headers = []har.NameValue{{Name: "Set-Cookie", Value: "session=" + fakeCookie + "; Path=/; SameSite=None; Secure"}}
	home.Response.Content = har.Content{MimeType: "text/html", Text: "<p>Welcome alice@example.com</p>"}

	callback := testutil.GetEntry(t, "https://app.example.com/cb?code="+fakeCode+"&state=st-123&client_id=app-1", at, 302)
	implicit := testutil.GetEntry(t, "https://app.example.com/cb#id_token="+fakeJWT+"&state=st-456", at, 200)
	denied := testutil.GetEntry(t, "https://app.example.com/cb?error=access_denied&error_description=AADSTS50105%3A+alice%40example.com+is+not+assigned", at, 200)

	form := testutil.PostFormEntry("https://idp.example.org/login",
		url.Values{"username": {"alice@example.com"}, "password": {fakePassword}}, at, 302)

	token := testutil.GetEntry(t, "https://idp.example.org/token", at, 400)
	token.Response.Content = har.Content{MimeType: "application/json", Text: `{"error":"invalid_grant","error_description":"bad code for alice@example.com"}`}

	errPage := testutil.GetEntry(t, "https://login.example.net/error", at, 400)
	errPage.Response.Content = har.Content{MimeType: "text/html", Text: "<p>AADSTS50011: reply URL mismatch for alice@example.com</p>"}

	// A new slice: appending to login's entries could write into its
	// backing array.
	entries := make([]har.Entry, 0, len(login.HAR.Log.Entries)+7)
	entries = append(entries, login.HAR.Log.Entries...)
	entries = append(entries, home, callback, implicit, denied, form, token, errPage)
	return testutil.NewHAR(entries...)
}

func redacted(t *testing.T, h *har.HAR, opts Options) *har.HAR {
	t.Helper()
	if opts.Salt == nil {
		opts.Salt = testSalt
	}
	out, err := Redact(h, opts)
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip through JSON, as the CLI does, so tests see what a reader
	// of the written file would see.
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	back, err := har.Decode(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("redacted HAR does not read back: %v", err)
	}
	return back
}

// TestRedactLeavesNoSecrets is the core property: whatever the redactor
// keeps, the scanner finds nothing in it.
func TestRedactLeavesNoSecrets(t *testing.T) {
	out := redacted(t, richHAR(t), Options{})
	if leaks := Scan(out); len(leaks) != 0 {
		for _, l := range leaks {
			t.Errorf("leak after redaction: %+v", l)
		}
	}
	b, _ := json.Marshal(out)
	for _, s := range []string{fakeJWT, fakeCookie, fakePassword, fakeCode, "opaque-token", "alice@example.com", "st-123"} {
		if bytes.Contains(b, []byte(s)) {
			t.Errorf("redacted output still contains %q", s)
		}
	}
}

func TestRedactKeepsWhatDiagnosisNeeds(t *testing.T) {
	out := redacted(t, richHAR(t), Options{})
	byURL := func(prefix string) *har.Entry {
		for i := range out.Log.Entries {
			if strings.HasPrefix(out.Log.Entries[i].Request.URL, prefix) {
				return &out.Log.Entries[i]
			}
		}
		t.Fatalf("no entry starting with %s", prefix)
		return nil
	}

	home := byURL("https://app.example.com/home")
	if c := home.Request.Cookies[0]; c.Name != "session" || c.Value != Redacted || !c.Secure || !c.HTTPOnly || c.Path != "/" {
		t.Errorf("cookie = %+v, want name and attributes kept, value redacted", c)
	}
	wantHeaders := map[string]string{
		"Cookie":        "session=[redacted]; theme=[redacted]",
		"Authorization": "[redacted] (Bearer)",
		"User-Agent":    "Mozilla/5.0 (synthetic)",
		"X-Request-Id":  Redacted,
	}
	for _, h := range home.Request.Headers {
		if want, ok := wantHeaders[h.Name]; ok && h.Value != want {
			t.Errorf("header %s = %q, want %q", h.Name, h.Value, want)
		}
	}
	if v, _ := home.Response.Header("Set-Cookie"); v != "session=[redacted]; Path=/; SameSite=None; Secure" {
		t.Errorf("Set-Cookie = %q", v)
	}
	if home.Response.Content.Text != "" || home.Response.Content.MimeType != "text/html" {
		t.Errorf("non-SSO body kept: %+v", home.Response.Content)
	}

	cb := byURL("https://app.example.com/cb?code")
	if v, _ := cb.Request.QueryParam("code"); v != Redacted {
		t.Errorf("code = %q", v)
	}
	if v, _ := cb.Request.QueryParam("client_id"); v != "app-1" {
		t.Errorf("client_id = %q, want it kept", v)
	}
	if len(cb.Request.QueryString) != 3 || cb.Request.QueryString[0].Name != "code" {
		t.Errorf("queryString = %+v, want all names kept in order", cb.Request.QueryString)
	}

	denied := byURL("https://app.example.com/cb?error")
	if v, _ := denied.Request.QueryParam("error"); v != "access_denied" {
		t.Errorf("error = %q, want the standard value kept", v)
	}
	if v, _ := denied.Request.QueryParam("error_description"); v != "AADSTS50105 [redacted]" {
		t.Errorf("error_description = %q, want only the code kept", v)
	}

	form := byURL("https://idp.example.org/login")
	if v, _ := form.Request.FormParam("password"); v != Redacted {
		t.Errorf("password = %q", v)
	}

	errPage := byURL("https://login.example.net/error")
	if !strings.Contains(errPage.Response.Content.Text, "AADSTS50011") || strings.Contains(errPage.Response.Content.Text, "reply URL") {
		t.Errorf("error page stub = %q, want only the code", errPage.Response.Content.Text)
	}
	tok := byURL("https://idp.example.org/token")
	if !strings.Contains(tok.Response.Content.Text, `"error":"invalid_grant"`) {
		t.Errorf("token error stub = %q", tok.Response.Content.Text)
	}
}

func TestRedactJWT(t *testing.T) {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	tok := enc(map[string]any{"alg": "RS256", "kid": "k1", "x5c": "cert-data"}) + "." +
		enc(map[string]any{"iss": "https://idp.example.org", "aud": "app-1", "exp": 1768471200, "sub": "user-123", "nonce": "n-1", "email": "alice@example.com", "name": "Alice"}) +
		".c2lnbmF0dXJl"
	r := &redactor{salt: testSalt}
	out := r.jwt(tok)

	parts := strings.Split(out, ".")
	if len(parts) != 3 || parts[2] != jwtSigMarker {
		t.Fatalf("redacted JWT = %q", out)
	}
	var header, claims map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(hb, &header)
	_ = json.Unmarshal(cb, &claims)

	if header["alg"] != "RS256" || header["kid"] != "k1" || header["x5c"] != nil {
		t.Errorf("header = %v", header)
	}
	if claims["iss"] != "https://idp.example.org" || claims["aud"] != "app-1" || claims["exp"] == nil {
		t.Errorf("diagnostic claims lost: %v", claims)
	}
	if s, _ := claims["sub"].(string); !strings.HasPrefix(s, maskPrefix) {
		t.Errorf("sub = %v, want masked", claims["sub"])
	}
	if claims["email"] != nil || claims["name"] != nil {
		t.Errorf("identifying claims kept: %v", claims)
	}
	if r.jwt("opaque-token-value") != Redacted {
		t.Error("non-JWT token not fully redacted")
	}
}

func TestRedactSAML(t *testing.T) {
	out := redacted(t, richHAR(t), Options{})
	post := &out.Log.Entries[1].Request
	b64, ok := post.FormParam("SAMLResponse")
	if !ok {
		t.Fatal("SAMLResponse missing after redaction")
	}
	raw, err := saml.DecodePOST(b64)
	if err != nil {
		t.Fatal(err)
	}
	xml := string(raw)
	for _, want := range []string{sigVerified, "@" + maskDomain, "X509Certificate", "https://app.example.org/saml/metadata", "SessionIndex=\"" + maskPrefix} {
		if !strings.Contains(xml, want) {
			t.Errorf("redacted SAML missing %q", want)
		}
	}
	if strings.Contains(xml, "alice@example.com") {
		t.Error("redacted SAML still names the user")
	}

	// The Redirect-binding AuthnRequest must still decode (re-deflated).
	get := &out.Log.Entries[0].Request
	req, _ := get.QueryParam("SAMLRequest")
	if _, err := saml.DecodeRedirect(req); err != nil {
		t.Errorf("redacted SAMLRequest no longer decodes: %v", err)
	}
}

// TestRedactMaskCorrelates: the same NameID in two messages gets the same
// mask in one run, and a different mask with a different salt.
func TestRedactMaskCorrelates(t *testing.T) {
	a := &redactor{salt: []byte("salt-a")}
	b := &redactor{salt: []byte("salt-b")}
	first, second := a.mask("alice@example.com"), a.mask("alice@example.com")
	if first != second {
		t.Error("same input, same salt: masks differ")
	}
	if a.mask("alice@example.com") == a.mask("bob@example.com") {
		t.Error("different users got the same mask")
	}
	if a.mask("alice@example.com") == b.mask("alice@example.com") {
		t.Error("different salts gave the same mask; the salt is not being used")
	}
}

func TestRedactDoesNotModifyInput(t *testing.T) {
	h := richHAR(t)
	before, _ := json.Marshal(h)
	_ = redacted(t, h, Options{})
	after, _ := json.Marshal(h)
	if !bytes.Equal(before, after) {
		t.Error("Redact modified its input")
	}
}

// TestRedactKeepBodies: kept bodies still go through the scan, which is
// what makes --keep-bodies safe to offer.
func TestRedactKeepBodies(t *testing.T) {
	out := redacted(t, richHAR(t), Options{KeepBodies: true})
	if len(Scan(out)) == 0 {
		t.Error("bodies with an email were kept but the scan found nothing")
	}
}

// TestRedactScrubsKeptFields covers the places the fuzzer found: values
// the redactor keeps verbatim (URL paths, opaque URLs, safe headers, cookie
// attributes) must still lose any JWT or email address inside them.
func TestRedactScrubsKeptFields(t *testing.T) {
	e := testutil.GetEntry(t, "https://app.example.com/users/alice@example.com/magic/"+fakeJWT, testutil.RefTime, 200)
	e.Request.Headers = []har.NameValue{{Name: "Origin", Value: "https://alice@example.com"}}
	e.Response.Headers = []har.NameValue{{Name: "Set-Cookie", Value: "s=1; Domain=" + fakeJWT}}
	mailto := testutil.GetEntry(t, "https://app.example.com/", testutil.RefTime, 302)
	mailto.Response.RedirectURL = "mailto:alice@example.com"

	out := redacted(t, testutil.NewHAR(e, mailto), Options{})
	if leaks := Scan(out); len(leaks) != 0 {
		t.Fatalf("leaks after redaction: %+v", leaks)
	}
	got := out.Log.Entries[0].Request.URL
	if !strings.Contains(got, "/users/u-") || !strings.Contains(got, "@"+maskDomain) || !strings.HasPrefix(got, "https://app.example.com/") {
		t.Errorf("URL = %q, want host kept and the email in the path masked", got)
	}
}
