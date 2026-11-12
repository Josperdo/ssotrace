package diagnose

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Josperdo/ssotrace/internal/flow"
	"github.com/Josperdo/ssotrace/internal/har"
	"github.com/Josperdo/ssotrace/internal/testutil"
)

// One IdP key for the whole package: RSA key generation is the slowest part
// of these tests, and no test depends on a fresh key.
var (
	idpOnce sync.Once
	idpKey  *testutil.KeyPair
)

func testIDP(t *testing.T) *testutil.KeyPair {
	t.Helper()
	idpOnce.Do(func() { idpKey = testutil.NewKeyPair(t, "idp.example.com") })
	return idpKey
}

// login describes one SSO attempt to put in a capture. Zero values mean
// "normal": a default AuthnRequest answered by a default, assertion-signed
// Response posted to the SP's ACS URL.
type login struct {
	noRequest  bool                                // IdP-initiated, or request not captured
	noResponse bool                                // the IdP never answered
	reqStatus  int                                 // IdP's HTTP status for the request; default 200
	postURL    string                              // where the browser posted the Response; default the ACS URL
	req        func(*testutil.AuthnRequestOptions) // tweak the request
	resp       func(*testutil.ResponseOptions)     // tweak the response
	mutate     func([]byte) []byte                 // edit the Response XML after signing
}

// samlCtx turns logins into a Context the way the CLI does: build a HAR,
// then trace it.
func samlCtx(t *testing.T, logins ...login) Context {
	t.Helper()
	var entries []har.Entry
	at := testutil.RefTime
	for _, l := range logins {
		ro := testutil.DefaultAuthnRequestOptions()
		if l.req != nil {
			l.req(&ro)
		}
		if !l.noRequest {
			status := l.reqStatus
			if status == 0 {
				status = 200
			}
			u := testutil.RedirectURL(t, ro.Destination, testutil.AuthnRequest(t, ro), "", nil)
			entries = append(entries, testutil.GetEntry(t, u, at, status))
		}
		if l.noResponse {
			continue
		}
		po := testutil.DefaultResponseOptions()
		if l.noRequest {
			po.InResponseTo = ""
		}
		if l.resp != nil {
			l.resp(&po)
		}
		xml := testutil.Response(t, testIDP(t), po)
		if l.mutate != nil {
			xml = l.mutate(xml)
		}
		post := l.postURL
		if post == "" {
			post = "https://app.example.org/saml/acs"
		}
		form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(xml)}}
		entries = append(entries, testutil.PostFormEntry(post, form, at.Add(time.Second), 302))
		at = at.Add(time.Minute)
	}
	h := testutil.NewHAR(entries...)
	return Context{HAR: h, SAML: flow.TraceSAML(h)}
}

type ruleCase struct {
	name     string
	logins   []login
	wantSev  Severity
	wantText string // substring of Title, Detail, or any evidence value
}

// runRuleCases checks that rule r yields exactly one finding per case with
// the wanted severity.
func runRuleCases(t *testing.T, r Rule, cases []ruleCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := only(t, r, samlCtx(t, tc.logins...))
			if f.Severity != tc.wantSev {
				t.Errorf("severity = %v, want %v\n%+v", f.Severity, tc.wantSev, f)
			}
			if tc.wantText != "" && !findingMentions(f, tc.wantText) {
				t.Errorf("finding does not mention %q:\n%+v", tc.wantText, f)
			}
			if f.Severity == Fail && f.Fix == "" {
				t.Error("FAIL finding has no fix text")
			}
		})
	}
}

func findingMentions(f Finding, s string) bool {
	if strings.Contains(f.Title, s) || strings.Contains(f.Detail, s) {
		return true
	}
	for _, e := range f.Evidence {
		if strings.Contains(e.Value, s) {
			return true
		}
	}
	return false
}

var normal = login{}

func TestSAML001Status(t *testing.T) {
	runRuleCases(t, statusNotSuccess{}, []ruleCase{
		{"success", []login{normal}, Pass, ""},
		{"user not assigned", []login{{resp: func(o *testutil.ResponseOptions) {
			o.StatusCode = "urn:oasis:names:tc:SAML:2.0:status:Responder"
			o.StatusSubCode = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
			o.StatusMessage = "User is not assigned to this application"
		}}}, Fail, "not assigned"},
		{"bad request, no sub-code", []login{{resp: func(o *testutil.ResponseOptions) {
			o.StatusCode = testutil.StatusRequester
		}}}, Fail, "SP's request"},
	})
}

func TestSAML002Audience(t *testing.T) {
	wrongAudience := func(o *testutil.ResponseOptions) { o.Audience = "urn:example:some-other-app" }
	runRuleCases(t, audienceMismatch{}, []ruleCase{
		{"matches request issuer", []login{normal}, Pass, ""},
		{"wrong audience", []login{{resp: wrongAudience}}, Fail, "urn:example:some-other-app"},
		{"idp-initiated, nothing to compare", []login{{noRequest: true}}, Info, "could not be checked"},
		{
			"idp-initiated, SP known from another request to the same ACS",
			[]login{normal, {noRequest: true, resp: wrongAudience}},
			Fail, "same ACS URL",
		},
	})
}

func TestSAML003Destination(t *testing.T) {
	runRuleCases(t, destinationMismatch{}, []ruleCase{
		{"matches", []login{normal}, Pass, ""},
		{"default port written out", []login{{resp: func(o *testutil.ResponseOptions) {
			o.Destination = "https://APP.example.org:443/saml/acs"
		}}}, Pass, ""},
		{"http behind a TLS proxy", []login{{resp: func(o *testutil.ResponseOptions) {
			o.Destination = "http://app.example.org/saml/acs"
		}}}, Fail, "scheme differs"},
		{"different host", []login{{postURL: "https://new.example.org/saml/acs"}}, Fail, "host differs"},
	})
}

func TestSAML004Recipient(t *testing.T) {
	runRuleCases(t, recipientMismatch{}, []ruleCase{
		{"matches", []login{normal}, Pass, ""},
		{"trailing slash", []login{{resp: func(o *testutil.ResponseOptions) {
			o.Recipient = "https://app.example.org/saml/acs/"
		}}}, Fail, "trailing slash"},
		{"different path", []login{{resp: func(o *testutil.ResponseOptions) {
			o.Recipient = "https://app.example.org/sso/consume"
		}}}, Fail, "path differs"},
	})
}

func TestSAML005Correlation(t *testing.T) {
	runRuleCases(t, correlation{}, []ruleCase{
		{"answered", []login{normal}, Pass, ""},
		{"idp rejected the request", []login{{noResponse: true, reqStatus: 400}}, Fail, "400"},
		{"never answered", []login{{noResponse: true}}, Warn, "never answered"},
		{"idp-initiated", []login{{noRequest: true}}, Info, "IdP-initiated"},
		{"request not captured", []login{{noRequest: true, resp: func(o *testutil.ResponseOptions) {
			o.InResponseTo = "_not-in-capture"
		}}}, Warn, "_not-in-capture"},
	})
}

func TestSAML007Unsigned(t *testing.T) {
	runRuleCases(t, unsigned{}, []ruleCase{
		{"assertion signed", []login{normal}, Pass, ""},
		{"only response signed", []login{{resp: func(o *testutil.ResponseOptions) {
			o.SignAssertion, o.SignResponse = false, true
		}}}, Pass, ""},
		{"nothing signed", []login{{resp: func(o *testutil.ResponseOptions) { o.SignAssertion = false }}}, Fail, "not signed"},
	})
}

func TestSAML008InvalidSignature(t *testing.T) {
	tamper := func(b []byte) []byte {
		return bytes.Replace(b, []byte("alice@example.com"), []byte("mallory@example.com"), 1)
	}
	runRuleCases(t, invalidSignature{}, []ruleCase{
		{"verifies", []login{normal}, Pass, "not that the signer is the IdP"},
		{"altered after signing", []login{{mutate: tamper}}, Fail, "could not be verified"},
	})
	if got := (invalidSignature{}).Check(samlCtx(t, login{resp: func(o *testutil.ResponseOptions) { o.SignAssertion = false }})); got != nil {
		t.Errorf("no signatures at all: got %+v, want nothing (that is SAML007's job)", got)
	}
}

func TestSAML010WeakAlgorithm(t *testing.T) {
	runRuleCases(t, weakAlgorithm{}, []ruleCase{
		{"sha-256", []login{normal}, Pass, ""},
		{"sha-1", []login{{resp: func(o *testutil.ResponseOptions) { o.SHA1 = true }}}, Warn, "RSA-SHA1"},
	})
}

func TestSAML011Encrypted(t *testing.T) {
	runRuleCases(t, encryptedAssertion{}, []ruleCase{
		{"encrypted", []login{{resp: func(o *testutil.ResponseOptions) { o.Encrypt = true }}}, Info, "encrypted"},
	})
	if got := (encryptedAssertion{}).Check(samlCtx(t, normal)); got != nil {
		t.Errorf("plain assertion: got %+v, want nothing", got)
	}
}

func TestSAML012NameID(t *testing.T) {
	askFor := func(format string) func(*testutil.AuthnRequestOptions) {
		return func(o *testutil.AuthnRequestOptions) { o.NameIDFormat = format }
	}
	runRuleCases(t, nameIDProblems{}, []ruleCase{
		{"no policy requested", []login{normal}, Pass, ""},
		{"requested format sent", []login{{req: askFor(testutil.NameIDEmail)}}, Pass, ""},
		{"unspecified accepts anything", []login{{req: askFor(unspecifiedNameID)}}, Pass, ""},
		{"format differs", []login{{req: askFor(testutil.NameIDPersistent)}}, Fail, "persistent"},
		{"missing", []login{{resp: func(o *testutil.ResponseOptions) { o.NameID = "" }}}, Warn, "no NameID"},
	})
}

func TestSAML014MultipleAssertions(t *testing.T) {
	smuggle := func(b []byte) []byte {
		extra := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_extra" Version="2.0" IssueInstant="2026-01-15T10:00:00Z">` +
			`<saml:Issuer>https://idp.example.com/saml</saml:Issuer></saml:Assertion>`
		i := bytes.Index(b, []byte("<saml:Assertion"))
		return append(append(append([]byte{}, b[:i]...), extra...), b[i:]...)
	}
	runRuleCases(t, multipleAssertions{}, []ruleCase{
		{"one", []login{normal}, Pass, ""},
		{"extra unsigned assertion", []login{{mutate: smuggle}}, Warn, "1 of 2 readable"},
	})
}

// TestSAMLRulesQuietWithoutSAML: a capture with no SAML is HAR001's
// finding. Every SAML rule must stay silent rather than pile on.
func TestSAMLRulesQuietWithoutSAML(t *testing.T) {
	reg, err := DefaultRules()
	if err != nil {
		t.Fatal(err)
	}
	empty := Context{HAR: testutil.NewHAR(), SAML: flow.TraceSAML(testutil.NewHAR())}
	for _, r := range reg.Rules() {
		if !strings.HasPrefix(r.ID(), "SAML") {
			continue
		}
		for _, ctx := range []Context{{}, empty} {
			if got := r.Check(ctx); len(got) != 0 {
				t.Errorf("%s on a capture without SAML: %+v", r.ID(), got)
			}
		}
	}
}
