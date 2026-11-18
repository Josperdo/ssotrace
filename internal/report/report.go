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
	OIDC     *flow.OIDCTrace
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
// one section per SAML flow and one per OIDC flow, each in capture order.
// Every flow gets a section, even a clean one, so the reader can see each
// login was looked at.
func (r *Report) sections() []section {
	samlFlows := map[int][]diagnose.Finding{}
	oidcFlows := map[int][]diagnose.Finding{}
	var capture []diagnose.Finding
	for _, f := range r.Findings {
		switch {
		case f.Severity == diagnose.Pass:
		case f.Flow != nil:
			samlFlows[*f.Flow] = append(samlFlows[*f.Flow], f)
		case f.OIDCFlow != nil:
			oidcFlows[*f.OIDCFlow] = append(oidcFlows[*f.OIDCFlow], f)
		default:
			capture = append(capture, f)
		}
	}

	out := []section{{Title: "Capture", Findings: sortFindings(capture)}}
	if r.SAML != nil {
		for i := range r.SAML.Flows {
			out = append(out, section{
				Title:    flowTitle(i, &r.SAML.Flows[i]),
				Findings: sortFindings(samlFlows[i]),
			})
		}
	}
	if r.OIDC != nil {
		for i := range r.OIDC.Flows {
			out = append(out, section{
				Title:    oidcFlowTitle(i, &r.OIDC.Flows[i]),
				Findings: sortFindings(oidcFlows[i]),
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

// flowTitle names a SAML login attempt: "SAML login 1 · SP-initiated ·
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
	first := f.Request
	if first == nil {
		first = f.Response
	}
	var at string
	if first != nil {
		at = first.Time
	}
	return title(fmt.Sprintf("SAML login %d", i+1), kind, spHost(f), at)
}

// oidcFlowTitle names an OAuth/OIDC login attempt: "OIDC login 1 ·
// authorization code · app.example.org · 2026-01-15 10:00:00 UTC". A
// request without the openid scope is plain OAuth 2.0 and is called that;
// without the request, only an ID token proves the login was OIDC.
func oidcFlowTitle(i int, f *flow.OIDCFlow) string {
	proto, kind := "OAuth/OIDC", ""
	if (f.Callback != nil && f.Callback.Params.IDToken != nil) ||
		(f.Token != nil && f.Token.Response != nil && f.Token.Response.IDToken != nil) {
		proto = "OIDC"
	}
	var first *flow.Sent
	var appURL string
	switch {
	case f.Authorization != nil:
		a := f.Authorization.Params
		proto = "OAuth"
		if a.OpenID() {
			proto = "OIDC"
		}
		kind = responseTypeName(a.ResponseType)
		if f.Callback == nil {
			kind += ", no callback"
		}
		first, appURL = &f.Authorization.Sent, a.RedirectURI
	case f.Callback != nil && f.Repeats != nil:
		kind = fmt.Sprintf("callback loaded again (repeats login %d)", *f.Repeats+1)
		first, appURL = &f.Callback.Sent, f.Callback.URL
	case f.Callback != nil:
		kind = "callback to an uncaptured request"
		first, appURL = &f.Callback.Sent, f.Callback.URL
	case f.Token != nil:
		kind = "token call for an uncaptured login"
		first, appURL = &f.Token.Sent, f.Token.Request.RedirectURI
	}
	var at string
	if first != nil {
		at = first.Time
	}
	host := ""
	if u, err := url.Parse(appURL); err == nil {
		host = u.Host
	}
	return title(fmt.Sprintf("%s login %d", proto, i+1), kind, host, at)
}

// responseTypeName names the OAuth flow a response_type selects.
func responseTypeName(rt string) string {
	switch strings.Join(strings.Fields(rt), " ") {
	case "code":
		return "authorization code"
	case "token", "id_token", "id_token token", "token id_token":
		return "implicit"
	case "":
		return "no response_type"
	default:
		return "hybrid"
	}
}

// title joins the non-empty parts of a section title, rendering the HAR
// timestamp in UTC.
func title(name, kind, host, at string) string {
	parts := []string{name, kind}
	if host != "" {
		parts = append(parts, host)
	}
	if t, err := time.Parse(time.RFC3339Nano, at); err == nil {
		parts = append(parts, t.UTC().Format("2006-01-02 15:04:05 UTC"))
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

// loginCount describes how many login attempts were found, per protocol:
// "1 SAML login", "2 OAuth/OIDC logins", or both.
func (r *Report) loginCount() string {
	var nSAML, nOIDC int
	if r.SAML != nil {
		nSAML = len(r.SAML.Flows)
	}
	if r.OIDC != nil {
		nOIDC = len(r.OIDC.Flows)
	}
	if nSAML+nOIDC == 0 {
		return "no SAML or OAuth/OIDC logins found"
	}
	var parts []string
	if nSAML > 0 {
		parts = append(parts, plural(nSAML, "SAML login"))
	}
	if nOIDC > 0 {
		parts = append(parts, plural(nOIDC, "OAuth/OIDC login"))
	}
	return strings.Join(parts, " · ")
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
