package diagnose

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Josperdo/ssotrace/internal/har"
	"github.com/Josperdo/ssotrace/internal/testutil"
)

const formMIME = "application/x-www-form-urlencoded"

func entry(method, url string, bodySize int64, post *har.PostData) har.Entry {
	return har.Entry{Request: har.Request{Method: method, URL: url, BodySize: bodySize, PostData: post}}
}

func capture(entries ...har.Entry) Context {
	return Context{HAR: &har.HAR{Log: har.Log{Entries: entries}}}
}

// only runs one rule and requires exactly one finding.
func only(t *testing.T, r Rule, ctx Context) Finding {
	t.Helper()
	got := r.Check(ctx)
	if len(got) != 1 {
		t.Fatalf("%s returned %d findings, want 1: %+v", r.ID(), len(got), got)
	}
	if got[0].RuleID != r.ID() {
		t.Errorf("RuleID = %q, want %q", got[0].RuleID, r.ID())
	}
	return got[0]
}

func evidence(f Finding, label string) string {
	for _, e := range f.Evidence {
		if e.Label == label {
			return e.Value
		}
	}
	return ""
}

func TestHAR001(t *testing.T) {
	samlPost := entry("POST", "https://app.example.com/acs", 20, &har.PostData{MimeType: formMIME, Text: "SAMLResponse=abc"})
	authorize := entry("GET", "https://idp.example.org/authorize?client_id=c&response_type=code", 0, nil)
	plain := entry("GET", "https://app.example.com/home", 0, nil)

	tests := []struct {
		name       string
		ctx        Context
		wantSev    Severity
		wantDetail string // substring
		wantHosts  string // "" = no hosts evidence expected
	}{
		{"saml present", capture(plain, samlPost), Pass, "1 SAML and 0 OAuth/OIDC", ""},
		{"oidc present", capture(authorize), Pass, "0 SAML and 1 OAuth/OIDC", ""},
		{"empty capture", capture(), Fail, "no requests at all", ""},
		{"only plain traffic", capture(plain, entry("GET", "https://cdn.example.net/app.js", 0, nil)), Fail, "None of the 2 requests", "app.example.com, cdn.example.net"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := only(t, noSSOTraffic{}, tt.ctx)
			if f.Severity != tt.wantSev {
				t.Errorf("Severity = %v, want %v", f.Severity, tt.wantSev)
			}
			if !strings.Contains(f.Detail, tt.wantDetail) {
				t.Errorf("Detail = %q, want it to contain %q", f.Detail, tt.wantDetail)
			}
			if got := evidence(f, "Hosts in capture"); got != tt.wantHosts {
				t.Errorf("hosts evidence = %q, want %q", got, tt.wantHosts)
			}
			if f.Severity == Fail && !strings.Contains(f.Fix, "Preserve log") {
				t.Errorf("Fix should mention Preserve log: %q", f.Fix)
			}
		})
	}
}

func TestHAR001HostsSummary(t *testing.T) {
	var entries []har.Entry
	for i := 7; i >= 1; i-- {
		entries = append(entries, entry("GET", fmt.Sprintf("https://h%d.example.com/", i), 0, nil))
	}
	// Credentials in a URL must never reach the evidence.
	entries = append(entries, entry("GET", "https://user:hunter2@h1.example.com/?token=SECRET", 0, nil))

	got := hostsSummary(entries)
	want := "h1.example.com, h2.example.com, h3.example.com, h4.example.com, h5.example.com (+2 more)"
	if got != want {
		t.Errorf("hostsSummary = %q, want %q", got, want)
	}
	if strings.Contains(got, "hunter2") || strings.Contains(got, "SECRET") {
		t.Errorf("hostsSummary leaked a secret: %q", got)
	}
}

func TestHAR002(t *testing.T) {
	captured := entry("POST", "https://app.example.com/acs", 20, &har.PostData{MimeType: formMIME, Text: "SAMLResponse=abc"})
	capturedParams := entry("POST", "https://app.example.com/cb", 20, &har.PostData{MimeType: formMIME, Params: []har.Param{{Name: "code", Value: "x"}}})
	noPostData := entry("POST", "https://app.example.com/acs?token=SECRET", 20, nil)
	emptyPostData := entry("POST", "https://idp.example.org/token", 50, &har.PostData{MimeType: formMIME})
	unknownSize := entry("POST", "https://app.example.com/beacon", -1, nil)
	get := entry("GET", "https://app.example.com/home", 0, nil)

	tests := []struct {
		name        string
		ctx         Context
		wantSev     Severity
		wantCount   string // "Requests without a captured body" evidence
		wantExample string // first Example evidence
	}{
		{"all bodies captured", capture(get, captured, capturedParams), Pass, "", ""},
		{"no bodies sent", capture(get), Pass, "", ""},
		{"unknown size is not flagged", capture(unknownSize), Pass, "", ""},
		{"postData missing", capture(captured, noPostData), Warn, "1 of 2", "POST https://app.example.com/acs"},
		{"postData empty", capture(emptyPostData), Warn, "1 of 1", "POST https://idp.example.org/token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := only(t, missingRequestBodies{}, tt.ctx)
			if f.Severity != tt.wantSev {
				t.Errorf("Severity = %v, want %v", f.Severity, tt.wantSev)
			}
			if got := evidence(f, "Requests without a captured body"); got != tt.wantCount {
				t.Errorf("count evidence = %q, want %q", got, tt.wantCount)
			}
			if got := evidence(f, "Example"); got != tt.wantExample {
				t.Errorf("example evidence = %q, want %q", got, tt.wantExample)
			}
			for _, e := range f.Evidence {
				if strings.Contains(e.Value, "SECRET") {
					t.Errorf("evidence leaked the query string: %q", e.Value)
				}
			}
		})
	}
}

func TestHAR002ExampleLimit(t *testing.T) {
	var entries []har.Entry
	for i := range 5 {
		entries = append(entries, entry("POST", fmt.Sprintf("https://app.example.com/p%d", i), 10, nil))
	}
	f := only(t, missingRequestBodies{}, capture(entries...))
	examples := 0
	for _, e := range f.Evidence {
		if e.Label == "Example" {
			examples++
		}
	}
	if examples != maxExamplesShown {
		t.Errorf("examples = %d, want %d", examples, maxExamplesShown)
	}
}

func TestRulesTolerateNilHAR(t *testing.T) {
	reg, err := DefaultRules()
	if err != nil {
		t.Fatal(err)
	}
	if got := Run(Context{}, reg); len(got) != 0 {
		t.Errorf("Run with nil HAR = %+v, want no findings", got)
	}
}

func TestRunUsesDefaultRulesInOrder(t *testing.T) {
	reg, err := DefaultRules()
	if err != nil {
		t.Fatal(err)
	}
	got := Run(capture(), reg)
	var ids []string
	for _, f := range got {
		ids = append(ids, f.RuleID)
	}
	if strings.Join(ids, ",") != "HAR001,HAR002" {
		t.Errorf("rule order = %v, want [HAR001 HAR002]", ids)
	}
	if !HasFailures(got) {
		t.Error("empty capture should produce a FAIL (HAR001)")
	}
}

// hop builds an entry answered with status at RefTime + offset.
func hop(method, rawURL string, status int, offset time.Duration) har.Entry {
	e := entry(method, rawURL, 0, nil)
	e.StartedDateTime = testutil.RefTime.Add(offset).Format(time.RFC3339Nano)
	e.Response.Status = status
	return e
}

// loopRound is one automatic round trip: app redirects to the IdP, the IdP
// redirects back, and the app redirects to the IdP again.
func loopRound(start time.Duration) []har.Entry {
	return []har.Entry{
		hop("GET", "https://app.example.com/login?state=x"+start.String(), 302, start),
		hop("GET", "https://idp.example.org/authorize?client_id=c&response_type=code", 302, start+time.Second),
		hop("GET", "https://app.example.com/callback?code=abc&state=x", 302, start+2*time.Second),
	}
}

func TestHAR003RedirectLoop(t *testing.T) {
	var fast, slow []har.Entry
	for i := 0; i < 4; i++ {
		fast = append(fast, loopRound(time.Duration(i)*3*time.Second)...)
		slow = append(slow, loopRound(time.Duration(i)*2*time.Minute)...)
	}
	var polling []har.Entry
	for i := 0; i < 10; i++ {
		polling = append(polling, hop("GET", "https://app.example.com/api/status", 200, time.Duration(i)*time.Second))
	}

	tests := []struct {
		name     string
		ctx      Context
		want     Severity
		wantNil  bool
		wantText string
	}{
		{name: "automatic loop", ctx: capture(fast...), want: Fail, wantText: "4 in 9 seconds"},
		{name: "two rounds is a retry, not a loop", ctx: capture(fast[:6]...), want: Pass},
		{name: "person retrying slowly", ctx: capture(slow...), want: Pass},
		{name: "polling is not a sign-in hop", ctx: capture(polling...), wantNil: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantNil {
				if got := (redirectLoop{}).Check(tt.ctx); got != nil {
					t.Fatalf("got %+v, want nothing", got)
				}
				return
			}
			f := only(t, redirectLoop{}, tt.ctx)
			if f.Severity != tt.want {
				t.Errorf("severity = %v, want %v\n%+v", f.Severity, tt.want, f)
			}
			if tt.wantText != "" && !findingMentions(f, tt.wantText) {
				t.Errorf("finding does not mention %q:\n%+v", tt.wantText, f)
			}
			if f.Severity == Fail && strings.Contains(evidence(f, "Repeated request"), "?") {
				t.Errorf("evidence includes a query string: %q", evidence(f, "Repeated request"))
			}
		})
	}
}

func TestHAR004ErrorCodes(t *testing.T) {
	withBody := func(e har.Entry, mime, text string) har.Entry {
		e.Response.Content = har.Content{MimeType: mime, Text: text}
		return e
	}
	get := func(u string) har.Entry { return hop("GET", u, 200, 0) }

	tests := []struct {
		name     string
		ctx      Context
		want     Severity
		wantCode string
	}{
		{"clean", capture(get("https://app.example.com/home")), Pass, ""},
		{"entra code in redirect URL", capture(get("https://app.example.com/cb?error=invalid_request&error_description=AADSTS50011%3a+The+reply+URL")), Warn, "AADSTS50011"},
		{"adfs code in error page", capture(withBody(get("https://sts.example.com/adfs/ls"), "text/html", "<p>Event ID MSIS7012 occurred</p>")), Warn, "MSIS7012"},
		{"okta code in json", capture(withBody(get("https://idp.example.org/api"), "application/json", `{"errorCode":"E0000004"}`)), Warn, "E0000004"},
		{"oauth callback error", capture(get("https://app.example.com/cb?error=access_denied&state=s")), Warn, "access_denied"},
		{"token endpoint json error", capture(withBody(get("https://idp.example.org/token"), "application/json", `{"error": "invalid_grant"}`)), Warn, "invalid_grant"},
		{"codes inside a script bundle are ignored", capture(withBody(get("https://idp.example.org/app.js"), "application/javascript", `var codes=["AADSTS50011","AADSTS50058"]`)), Pass, ""},
		{"unknown error value ignored", capture(get("https://app.example.com/page?error=1")), Pass, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := only(t, idpErrorCodes{}, tt.ctx)
			if f.Severity != tt.want {
				t.Errorf("severity = %v, want %v\n%+v", f.Severity, tt.want, f)
			}
			if tt.wantCode != "" && evidence(f, tt.wantCode) == "" {
				t.Errorf("no evidence for %s: %+v", tt.wantCode, f.Evidence)
			}
		})
	}

	// The same code on two pages is one finding with one evidence line.
	twice := capture(get("https://a.example.com/x?e=AADSTS50011"), get("https://b.example.com/y?e=AADSTS50011"))
	if f := only(t, idpErrorCodes{}, twice); len(f.Evidence) != 1 {
		t.Errorf("duplicate code listed %d times", len(f.Evidence))
	}
}
