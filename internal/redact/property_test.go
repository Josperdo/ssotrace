package redact

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Josperdo/ssotrace/internal/diagnose"
	"github.com/Josperdo/ssotrace/internal/flow"
	"github.com/Josperdo/ssotrace/internal/har"
	"github.com/Josperdo/ssotrace/internal/saml"
	"github.com/Josperdo/ssotrace/internal/testutil"
)

// scenario describes one capture to build: an optional AuthnRequest, an
// optional Response, and any extra entries.
type scenario struct {
	noRequest  bool
	noResponse bool
	reqStatus  int
	req        func(*testutil.AuthnRequestOptions)
	resp       func(*testutil.ResponseOptions)
	mutate     func([]byte) []byte
	idp        *testutil.KeyPair
	extra      func(t *testing.T) []har.Entry
}

func (s scenario) build(t *testing.T, defaultIDP *testutil.KeyPair) *har.HAR {
	t.Helper()
	var entries []har.Entry
	ro := testutil.DefaultAuthnRequestOptions()
	if s.req != nil {
		s.req(&ro)
	}
	if !s.noRequest {
		status := s.reqStatus
		if status == 0 {
			status = 200
		}
		u := testutil.RedirectURL(t, ro.Destination, testutil.AuthnRequest(t, ro), "/", nil)
		entries = append(entries, testutil.GetEntry(t, u, testutil.RefTime, status))
	}
	if !s.noResponse {
		po := testutil.DefaultResponseOptions()
		if s.noRequest {
			po.InResponseTo = ""
		}
		if s.resp != nil {
			s.resp(&po)
		}
		kp := s.idp
		if kp == nil {
			kp = defaultIDP
		}
		xml := testutil.Response(t, kp, po)
		if s.mutate != nil {
			xml = s.mutate(xml)
		}
		form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(xml)}, "RelayState": {"/"}}
		entries = append(entries, testutil.PostFormEntry(po.Destination, form, testutil.RefTime.Add(time.Second), 302))
	}
	if s.extra != nil {
		entries = append(entries, s.extra(t)...)
	}
	return testutil.NewHAR(entries...)
}

// verdicts diagnoses h the way the CLI does and returns each finding as
// "RULE severity", sorted. Evidence is left out on purpose: redaction
// changes evidence (masked names, no signature values) but must never
// change the verdict.
func verdicts(h *har.HAR) []string {
	reg, err := diagnose.DefaultRules()
	if err != nil {
		panic(err)
	}
	ctx := diagnose.Context{HAR: h, SAML: flow.TraceSAML(h), OIDC: flow.TraceOIDC(h), ClockSkew: diagnose.DefaultClockSkew}
	var out []string
	for _, f := range diagnose.Run(ctx, reg) {
		out = append(out, f.RuleID+" "+f.Severity.String())
	}
	sort.Strings(out)
	return out
}

// TestRedactionPreservesDiagnosis is redaction's central promise: a redacted file
// gives the same diagnosis as the original, and holds no secrets.
func TestRedactionPreservesDiagnosis(t *testing.T) {
	idp := testutil.NewKeyPair(t, "idp.example.com")
	ref := testutil.RefTime

	smuggle := func(b []byte) []byte {
		extra := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_extra" Version="2.0" IssueInstant="2026-01-15T10:00:00Z">` +
			`<saml:Issuer>https://idp.example.com/saml</saml:Issuer><saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject></saml:Assertion>`
		i := bytes.Index(b, []byte("<saml:Assertion"))
		return append(append(append([]byte{}, b[:i]...), extra...), b[i:]...)
	}
	loop := func(t *testing.T) []har.Entry {
		var es []har.Entry
		for i := 0; i < 4; i++ {
			at := ref.Add(time.Duration(i) * 3 * time.Second)
			a := testutil.GetEntry(t, "https://app.example.com/login?state=s"+fmt.Sprint(i), at, 302)
			b := testutil.GetEntry(t, "https://idp.example.org/authorize?client_id=c&response_type=code&state=s", at.Add(time.Second), 302)
			es = append(es, a, b)
		}
		return es
	}
	errorPages := func(t *testing.T) []har.Entry {
		page := testutil.GetEntry(t, "https://login.example.net/error", ref, 400)
		page.Response.Content = har.Content{MimeType: "text/html", Text: "<p>AADSTS50011: no reply URL for alice@example.com</p>"}
		cb := testutil.GetEntry(t, "https://app.example.com/cb?error=access_denied&error_description=MSIS7012+denied&state=s", ref, 200)
		return []har.Entry{page, cb}
	}

	scenarios := map[string]scenario{
		"clean sp-initiated login": {},
		"unsigned assertion":       {resp: func(o *testutil.ResponseOptions) { o.SignAssertion = false }},
		"only response signed":     {resp: func(o *testutil.ResponseOptions) { o.SignAssertion, o.SignResponse = false, true }},
		"both signed":              {resp: func(o *testutil.ResponseOptions) { o.SignResponse = true }},
		"tampered signature": {mutate: func(b []byte) []byte {
			return bytes.Replace(b, []byte("alice@example.com"), []byte("mallory@example.com"), 1)
		}},
		"sha-1 signature":     {resp: func(o *testutil.ResponseOptions) { o.SHA1 = true }},
		"expired certificate": {idp: testutil.NewKeyPairValid(t, "old-idp.example.com", ref.AddDate(-2, 0, 0), ref.AddDate(0, 0, -3))},
		"wrong audience":      {resp: func(o *testutil.ResponseOptions) { o.Audience = "urn:example:other-app" }},
		"wrong destination":   {resp: func(o *testutil.ResponseOptions) { o.Destination = "http://app.example.org/saml/acs" }},
		"idp refused the login": {resp: func(o *testutil.ResponseOptions) {
			o.StatusCode = "urn:oasis:names:tc:SAML:2.0:status:Responder"
			o.StatusSubCode = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
			o.StatusMessage = "alice@example.com is not assigned"
		}},
		"encrypted assertion":      {resp: func(o *testutil.ResponseOptions) { o.Encrypt = true }},
		"idp-initiated":            {noRequest: true},
		"idp rejected the request": {noResponse: true, reqStatus: 400},
		"extra assertion":          {mutate: smuggle},
		"expired assertion": {resp: func(o *testutil.ResponseOptions) {
			o.IssueInstant = ref.Add(-20 * time.Minute)
			o.NotBefore = ref.Add(-21 * time.Minute)
			o.NotOnOrAfter = ref.Add(-15 * time.Minute)
		}},
		"nameid format mismatch": {req: func(o *testutil.AuthnRequestOptions) { o.NameIDFormat = testutil.NameIDPersistent }},
		"redirect loop":          {noRequest: true, noResponse: true, extra: loop},
		"idp error codes":        {extra: errorPages},
	}

	names := make([]string, 0, len(scenarios))
	for n := range scenarios {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			original := scenarios[name].build(t, idp)
			out := redacted(t, original, Options{})

			if leaks := Scan(out); len(leaks) != 0 {
				t.Errorf("redacted file still has secrets: %+v", leaks)
			}
			want, got := verdicts(original), verdicts(out)
			if strings.Join(want, ",") != strings.Join(got, ",") {
				t.Errorf("diagnosis changed by redaction\n original: %v\n redacted: %v", want, got)
			}
		})
	}

	// The rich capture too: cookies, tokens, forms, and bodies around a
	// SAML login.
	t.Run("rich capture", func(t *testing.T) {
		original := richHAR(t)
		want, got := verdicts(original), verdicts(redacted(t, original, Options{}))
		if strings.Join(want, ",") != strings.Join(got, ",") {
			t.Errorf("diagnosis changed by redaction\n original: %v\n redacted: %v", want, got)
		}
	})
}

// TestRedactTwice: redacting an already-redacted file changes nothing that
// matters. In particular a "verified" marker must not be downgraded.
func TestRedactTwice(t *testing.T) {
	once := redacted(t, richHAR(t), Options{})
	twice := redacted(t, once, Options{})
	if a, b := verdicts(once), verdicts(twice); strings.Join(a, ",") != strings.Join(b, ",") {
		t.Errorf("second redaction changed the diagnosis\n once:  %v\n twice: %v", a, b)
	}
	// The marker is inside the base64 SAMLResponse, so decode it first.
	v, ok := twice.Log.Entries[1].Request.FormParam("SAMLResponse")
	if !ok {
		t.Fatal("SAMLResponse missing")
	}
	raw, err := saml.DecodePOST(v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(sigVerified)) || bytes.Contains(raw, []byte(sigUnverified)) {
		t.Error("verified marker lost or downgraded on second redaction")
	}
}

// TestRedactionPreservesOIDCDiagnosis is the same promise for OAuth/OIDC:
// every break scenario reaches the same verdicts after redaction, and the
// redacted file passes the leak scan.
func TestRedactionPreservesOIDCDiagnosis(t *testing.T) {
	idp := testutil.NewKeyPair(t, "idp.example.com")
	tokenAt := testutil.RefTime.Add(12 * time.Second)
	scenarios := map[string]struct {
		edit func(*testutil.OIDCLoginOptions)
		har  func(*har.HAR)
	}{
		"clean code flow": {},
		"form_post":       {edit: func(o *testutil.OIDCLoginOptions) { o.Delivery = "form_post" }},
		"fragment":        {edit: func(o *testutil.OIDCLoginOptions) { o.Delivery = "fragment" }},
		"access denied": {edit: func(o *testutil.OIDCLoginOptions) {
			o.Error, o.ErrorDescription = "access_denied", "alice@example.com is not assigned"
		}},
		"state mismatch": {edit: func(o *testutil.OIDCLoginOptions) { o.CallbackState = testutil.Ptr("st-another-tab-0001") }},
		"nonce mismatch": {edit: func(o *testutil.OIDCLoginOptions) { o.IDTokenClaims = map[string]any{"nonce": "nonce-other-sign-in"} }},
		"wrong audience": {edit: func(o *testutil.OIDCLoginOptions) {
			o.IDTokenClaims = map[string]any{"aud": "other-app", "azp": "other-app"}
		}},
		"expired id token": {edit: func(o *testutil.OIDCLoginOptions) {
			o.IDTokenClaims = map[string]any{"iat": tokenAt.Add(-20 * time.Minute).Unix(), "exp": tokenAt.Add(-10 * time.Minute).Unix()}
		}},
		"no PKCE":               {edit: func(o *testutil.OIDCLoginOptions) { o.PKCE = false }},
		"browser client secret": {edit: func(o *testutil.OIDCLoginOptions) { o.ClientSecret = "s3cr3t-value-0123456789" }},
		"token redirect_uri differs": {edit: func(o *testutil.OIDCLoginOptions) {
			o.TokenRedirectURI = testutil.Ptr("https://app.example.org/callback/")
			o.TokenStatus, o.TokenBody = 400, `{"error":"invalid_grant","error_description":"Incorrect redirect_uri"}`
		}},
		"callback reloaded": {edit: func(o *testutil.OIDCLoginOptions) { o.Reloads = 2 }},
		"CORS blocked": {
			edit: func(o *testutil.OIDCLoginOptions) { o.TokenStatus, o.TokenBody = 403, " " },
			har: func(h *har.HAR) {
				e := &h.Log.Entries[len(h.Log.Entries)-1]
				e.Request.Headers = append(e.Request.Headers, har.NameValue{Name: "Origin", Value: "https://app.example.org"})
			},
		},
		"code already used": {edit: func(o *testutil.OIDCLoginOptions) {
			o.TokenStatus, o.TokenBody = 400, `{"error":"invalid_grant","error_description":"Code not valid"}`
		}},
		"redirect_uri not registered": {har: func(h *har.HAR) {
			e := h.Log.Entries[0]
			e.Response.Status = 400
			e.Response.Content = har.Content{MimeType: "text/html", Text: "<p>Invalid parameter: redirect_uri https://app.example.org/cb?code=opaque123</p>"}
			h.Log.Entries = []har.Entry{e}
		}},
	}
	names := make([]string, 0, len(scenarios))
	for n := range scenarios {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			s := scenarios[name]
			o := testutil.DefaultOIDCLoginOptions()
			o.IDP = idp
			if s.edit != nil {
				s.edit(&o)
			}
			original := testutil.NewOIDCLogin(t, o).HAR
			if s.har != nil {
				s.har(original)
			}
			out := redacted(t, original, Options{})

			if leaks := Scan(out); len(leaks) != 0 {
				t.Errorf("redacted file still has secrets: %+v", leaks)
			}
			want, got := verdicts(original), verdicts(out)
			if strings.Join(want, ",") != strings.Join(got, ",") {
				t.Errorf("diagnosis changed by redaction\n original: %v\n redacted: %v", want, got)
			}
			if !strings.Contains(strings.Join(want, ","), "OIDC") {
				t.Errorf("scenario produced no OIDC verdicts: %v", want)
			}
		})
	}
}

// TestRedactionKeepsKnowledgeBaseCodes checks that every code and known
// message HAR004 finds, including the knowledge base's pattern-less codes
// and exact messages, is still found in the redacted file.
func TestRedactionKeepsKnowledgeBaseCodes(t *testing.T) {
	page := func(rawURL, mime, body string) har.Entry {
		e := testutil.GetEntry(t, rawURL, testutil.RefTime, 200)
		e.Response.Content = har.Content{MimeType: mime, Text: body}
		return e
	}
	tests := map[string]har.Entry{
		"Google code on an error page": page("https://accounts.example.com/signin", "text/html",
			"<h1>Access blocked</h1><p>Error 403: org_internal</p><p>alice@example.com</p>"),
		"Google code in error_description": testutil.GetEntry(t,
			"https://app.example.com/cb?error=access_denied&error_description=admin_policy_enforced+for+alice%40example.com", testutil.RefTime, 200),
		"Google code in a JSON body": page("https://accounts.example.com/api", "application/json",
			`{"detail":"Error: disallowed_useragent","user":"alice@example.com"}`),
		"Keycloak message on a page": page("https://idp.example.com/realms/lab/login-actions/authenticate", "text/html",
			`<span id="input-error">Invalid username or password.</span><input name="username" value="alice">`),
		"Okta message in error_description": testutil.GetEntry(t,
			"https://app.example.com/cb?error=access_denied&error_description=User+is+not+assigned+to+the+client+application.", testutil.RefTime, 200),
		"Entra code with an explanation": testutil.GetEntry(t,
			"https://app.example.com/cb?error=access_denied&error_description=AADSTS50105%3a+alice%40example.com+is+not+assigned", testutil.RefTime, 200),
	}
	codes := func(h *har.HAR) []string {
		reg, err := diagnose.DefaultRules()
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, rule := range reg.Rules() {
			if rule.ID() != "HAR004" {
				continue
			}
			for _, f := range rule.Check(diagnose.Context{HAR: h}) {
				for _, e := range f.Evidence {
					if e.Label != "Meaning" {
						out = append(out, e.Label+"|"+strings.SplitN(e.Value, ",", 2)[0])
					}
				}
			}
		}
		return out
	}
	for name, e := range tests {
		t.Run(name, func(t *testing.T) {
			h := testutil.NewHAR(e)
			before := codes(h)
			if len(before) == 0 {
				t.Fatal("HAR004 found nothing in the original; the fixture is wrong")
			}
			after := codes(redacted(t, h, Options{}))
			if strings.Join(before, "\n") != strings.Join(after, "\n") {
				t.Errorf("HAR004 evidence changed by redaction:\nbefore %q\nafter  %q", before, after)
			}
		})
	}
}
