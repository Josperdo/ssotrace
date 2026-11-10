package diagnose

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Josperdo/ssotrace/internal/har"
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
