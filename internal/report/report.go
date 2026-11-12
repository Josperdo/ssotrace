package report

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Josperdo/ssotrace/internal/diagnose"
	"github.com/Josperdo/ssotrace/internal/flow"
)

// Report is everything a renderer needs. The renderers only format it;
// every decision about what is wrong was made by the rules.
type Report struct {
	File     string // base name of the input; never a full path, which can contain a username
	Version  string // ssotrace version, for the Markdown footer and JSON
	Findings []diagnose.Finding
	SAML     *flow.SAMLTrace
}

// Counts tallies findings by severity.
type Counts struct {
	Fail int `json:"fail"`
	Warn int `json:"warn"`
	Info int `json:"info"`
	Pass int `json:"pass"`
}

func (r *Report) counts() Counts {
	var c Counts
	for _, f := range r.Findings {
		switch f.Severity {
		case diagnose.Fail:
			c.Fail++
		case diagnose.Warn:
			c.Warn++
		case diagnose.Info:
			c.Info++
		case diagnose.Pass:
			c.Pass++
		}
	}
	return c
}

// section is one block of the human-readable report: the capture as a
// whole, or one login attempt.
type section struct {
	Title    string
	Findings []diagnose.Finding // problems only (no Pass), most severe first
}

// sections groups the non-passing findings: capture-wide ones first, then
// one section per SAML flow in capture order. Every flow gets a section,
// even a clean one, so the reader can see each login was looked at.
func (r *Report) sections() []section {
	byFlow := map[int][]diagnose.Finding{}
	var capture []diagnose.Finding
	for _, f := range r.Findings {
		if f.Severity == diagnose.Pass {
			continue
		}
		if f.Flow == nil {
			capture = append(capture, f)
		} else {
			byFlow[*f.Flow] = append(byFlow[*f.Flow], f)
		}
	}

	out := []section{{Title: "Capture", Findings: sortFindings(capture)}}
	if r.SAML != nil {
		for i := range r.SAML.Flows {
			out = append(out, section{
				Title:    flowTitle(i, &r.SAML.Flows[i]),
				Findings: sortFindings(byFlow[i]),
			})
		}
	}
	return out
}

// sortFindings orders by severity (FAIL first), then rule ID, keeping the
// rules' own order for ties so output is stable.
func sortFindings(fs []diagnose.Finding) []diagnose.Finding {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		return fs[i].RuleID < fs[j].RuleID
	})
	return fs
}

// flowTitle names a login attempt: "Login 1 · SP-initiated ·
// app.example.org · 2026-01-15 10:00:00 UTC".
func flowTitle(i int, f *flow.SAMLFlow) string {
	kind := "SP-initiated"
	switch {
	case f.IDPInitiated:
		kind = "IdP-initiated"
	case f.Request == nil:
		kind = "response to an uncaptured request"
	case f.Response == nil:
		kind = "no response"
	}
	parts := []string{fmt.Sprintf("Login %d", i+1), kind}
	if h := spHost(f); h != "" {
		parts = append(parts, h)
	}
	first := f.Request
	if first == nil {
		first = f.Response
	}
	if first != nil {
		if t, err := time.Parse(time.RFC3339Nano, first.Time); err == nil {
			parts = append(parts, t.UTC().Format("2006-01-02 15:04:05 UTC"))
		}
	}
	return strings.Join(parts, " · ")
}

// spHost is the application's host: where the Response was delivered, or
// where the request asked for it to be delivered.
func spHost(f *flow.SAMLFlow) string {
	if f.Response != nil {
		if u, err := url.Parse(f.Response.URL); err == nil && u.Host != "" {
			return u.Host
		}
	}
	if f.Request != nil && f.Request.Message != nil && f.Request.Message.AuthnRequest != nil {
		if u, err := url.Parse(f.Request.Message.AuthnRequest.ACSURL); err == nil && u.Host != "" {
			return u.Host
		}
	}
	return ""
}

// clean makes a string safe to print in a terminal or a ticket.
//
// Finding text can include values copied from the HAR (an Issuer, a status
// message, a URL), and a hostile HAR can put anything in them. Control
// characters are replaced so an embedded escape sequence cannot recolor,
// move the cursor, or rewrite the terminal title; Unicode bidirectional
// overrides are replaced so text cannot be made to display in a different
// order than it really has ("Trojan Source"). Newlines and tabs become
// spaces so a value cannot fake extra report lines.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case unicode.IsControl(r), isBidiControl(r):
			return '�'
		}
		return r
	}, s)
}

func isBidiControl(r rune) bool {
	return (r >= '\u202A' && r <= '\u202E') || (r >= '\u2066' && r <= '\u2069') || r == '\u200E' || r == '\u200F' || r == '\u061C'
}

// summaryLine is "1 failure · 2 warnings · 1 note · 16 checks passed".
func summaryLine(c Counts) string {
	var parts []string
	add := func(n int, one, many string) {
		if n == 1 {
			parts = append(parts, "1 "+one)
		} else if n > 1 {
			parts = append(parts, fmt.Sprintf("%d %s", n, many))
		}
	}
	add(c.Fail, "failure", "failures")
	add(c.Warn, "warning", "warnings")
	add(c.Info, "note", "notes")
	add(c.Pass, "check passed", "checks passed")
	if len(parts) == 0 {
		return "no checks ran"
	}
	return strings.Join(parts, " · ")
}

// loginCount describes how many SAML login attempts were found.
func (r *Report) loginCount() string {
	n := 0
	if r.SAML != nil {
		n = len(r.SAML.Flows)
	}
	switch n {
	case 0:
		return "no SAML logins found"
	case 1:
		return "1 SAML login"
	default:
		return fmt.Sprintf("%d SAML logins", n)
	}
}
