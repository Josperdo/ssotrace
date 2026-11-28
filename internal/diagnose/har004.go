package diagnose

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/Josperdo/ssotrace/internal/har"
	"github.com/Josperdo/ssotrace/internal/kb"
)

// idpErrorCodes is HAR004: an identity provider's own error code appears in
// the capture. These codes are often the single most useful clue, and they
// are easy to miss in a long HAR: in a redirect URL's error_description,
// or buried in an error page.
//
// The rule reports each code and where it was found. When the embedded
// knowledge base (internal/kb) knows a code, the finding also says what it
// means and how to fix it.
type idpErrorCodes struct{}

func (idpErrorCodes) ID() string { return "HAR004" }

// errorPattern is one vendor's error-code format.
type errorPattern struct {
	vendor string
	re     *regexp.Regexp
}

// Word boundaries keep these from matching inside longer tokens, such as a
// base64 blob that happens to contain "AADSTS". The raw URL is searched
// without unescaping: codes are letters and digits, which URL encoding
// leaves alone.
var errorPatterns = []errorPattern{
	{"Microsoft Entra ID", regexp.MustCompile(`\bAADSTS\d{5,6}\b`)},
	{"AD FS", regexp.MustCompile(`\bMSIS\d{4}\b`)},
	{"Okta", regexp.MustCompile(`\bE0000\d{3}\b`)},
}

// oauthErrors are the standard error values from OAuth 2.0 (RFC 6749) and
// OpenID Connect Core. Only these are reported, so an unrelated "error"
// parameter or JSON field does not raise a finding.
var oauthErrors = map[string]bool{
	"invalid_request": true, "unauthorized_client": true, "access_denied": true,
	"unsupported_response_type": true, "invalid_scope": true, "server_error": true,
	"temporarily_unavailable": true, "invalid_client": true, "invalid_grant": true,
	"unsupported_grant_type": true, "interaction_required": true, "login_required": true,
	"account_selection_required": true, "consent_required": true, "invalid_request_uri": true,
	"invalid_request_object": true, "request_not_supported": true,
	"request_uri_not_supported": true, "registration_not_supported": true,
}

const oauthVendor = "OAuth 2.0 / OIDC"

// jsonError matches an "error" field in a JSON body, as token endpoints
// return it.
var jsonError = regexp.MustCompile(`"error"\s*:\s*"([a-z_]{1,40})"`)

// maxBodyScan caps how much of each response body is searched. Error codes
// appear near the top of error pages; scanning a 50 MB download for them
// would only waste time.
const maxBodyScan = 1 << 20

// maxCodesShown limits how many distinct codes are listed.
const maxCodesShown = 5

// kbMatch finds what the knowledge base knows beyond the vendor patterns
// above: codes with no pattern of their own (Google's, such as
// org_internal) and exact messages (Keycloak's, such as "Client not
// found."). It is built once, from the embedded data.
type kbMatch struct {
	// inURL finds pattern-less codes anywhere in a URL. inBody finds them
	// in a page only as "Error: code" or "Error 403: code", the way error
	// pages print them: a bare word like org_internal could also be a
	// string in some page's inline script.
	inURL, inBody *regexp.Regexp
	vendor        map[string]string
	messages      []kb.Entry
}

var kbMatchers = sync.OnceValue(func() *kbMatch {
	base := kb.Default()
	m := &kbMatch{vendor: map[string]string{}, messages: base.Messages()}
	var codes []string
	for _, e := range base.Codes() {
		if matchesVendorPattern(e.Code) {
			continue // already found by its vendor's pattern
		}
		codes = append(codes, regexp.QuoteMeta(e.Code))
		m.vendor[e.Code] = e.Vendor
	}
	if len(codes) > 0 {
		alt := strings.Join(codes, "|")
		m.inURL = regexp.MustCompile(`\b(` + alt + `)\b`)
		m.inBody = regexp.MustCompile(`\bError(?: \d{3})?:\s*(` + alt + `)\b`)
	}
	return m
})

func matchesVendorPattern(code string) bool {
	for _, p := range errorPatterns {
		if p.re.MatchString(code) {
			return true
		}
	}
	return false
}

// found is one code or known message, and whose it is.
type found struct {
	code, vendor string
}

// findInURL returns the codes and known messages in a URL: vendor codes
// anywhere in it, and known messages in its error_description parameter.
func findInURL(raw string) []found {
	var out []found
	for _, p := range errorPatterns {
		for _, c := range p.re.FindAllString(raw, -1) {
			out = append(out, found{c, p.vendor})
		}
	}
	m := kbMatchers()
	if m.inURL != nil {
		for _, c := range m.inURL.FindAllString(raw, -1) {
			out = append(out, found{c, m.vendor[c]})
		}
	}
	if len(m.messages) > 0 {
		if u, err := url.Parse(raw); err == nil {
			out = append(out, findMessages(u.Query().Get("error_description"))...)
		}
	}
	return out
}

// findInBody returns the codes and known messages in a response body that
// scannableBody let through.
func findInBody(body, mimeType string) []found {
	var out []found
	for _, p := range errorPatterns {
		for _, c := range p.re.FindAllString(body, -1) {
			out = append(out, found{c, p.vendor})
		}
	}
	m := kbMatchers()
	if m.inBody != nil {
		for _, sm := range m.inBody.FindAllStringSubmatch(body, -1) {
			out = append(out, found{sm[1], m.vendor[sm[1]]})
		}
	}
	out = append(out, findMessages(body)...)
	if strings.Contains(mimeType, "json") {
		for _, sm := range jsonError.FindAllStringSubmatch(body, -1) {
			if oauthErrors[sm[1]] {
				out = append(out, found{sm[1], oauthVendor})
			}
		}
	}
	return out
}

func findMessages(text string) []found {
	if text == "" {
		return nil
	}
	var out []found
	for _, e := range kbMatchers().messages {
		if strings.Contains(text, e.Message) {
			out = append(out, found{e.Message, e.Vendor})
		}
	}
	return out
}

type codeHit struct {
	found
	where string
}

func (idpErrorCodes) Check(ctx Context) []Finding {
	if ctx.HAR == nil || len(ctx.HAR.Log.Entries) == 0 {
		return nil
	}
	var hits []codeHit
	seen := map[string]bool{}
	add := func(where string, fs ...found) {
		for _, f := range fs {
			if !seen[f.code] {
				seen[f.code] = true
				hits = append(hits, codeHit{f, where})
			}
		}
	}

	for i := range ctx.HAR.Log.Entries {
		e := &ctx.HAR.Log.Entries[i]
		loc := fmt.Sprintf("entry %d: %s", i, describeRequest(&e.Request))

		add(loc+" (URL)", findInURL(e.Request.URL)...)
		add(loc+" (redirect target)", findInURL(e.Response.RedirectURL)...)
		if v, ok := e.Request.QueryParam("error"); ok && oauthErrors[v] {
			add(loc+" (URL)", found{v, oauthVendor})
		}
		if v, ok := e.Request.FormParam("error"); ok && oauthErrors[v] {
			add(loc+" (form body)", found{v, oauthVendor})
		}
		if body := scannableBody(&e.Response.Content); body != "" {
			add(loc+" (response body)", findInBody(body, e.Response.Content.MimeType)...)
		}
	}

	if len(hits) == 0 {
		return []Finding{passFinding("HAR004", "No IdP error codes found",
			"No identity provider error codes, known error messages, or OAuth errors appear in URLs or response bodies.")}
	}
	return []Finding{errorCodeFinding(hits)}
}

// errorCodeFinding lists the codes and, for those the knowledge base
// knows, what they mean and how to fix them.
func errorCodeFinding(hits []codeHit) Finding {
	f := Finding{
		RuleID:   "HAR004",
		Severity: Warn,
		Title:    "IdP error code found",
		Detail: fmt.Sprintf("The capture contains %s from the identity provider. The code usually names the exact problem, "+
			"even when the page the user saw was generic.", plural(len(hits), "error code")),
	}
	const lookUp = "Look up the code in the identity provider's documentation, or search the IdP's sign-in logs for it at the time of the capture."

	base := kb.Default()
	var explained []kb.Entry
	unknown := 0
	for i, h := range hits {
		if i == maxCodesShown {
			f.Evidence = append(f.Evidence, Evidence{Label: "More codes", Value: fmt.Sprintf("%d not shown", len(hits)-maxCodesShown)})
			break
		}
		entry, known := base.Lookup(h.code)
		if entry.Message != "" {
			f.Evidence = append(f.Evidence, Evidence{Label: "Message", Value: fmt.Sprintf("%q, %s, %s", h.code, h.vendor, h.where)})
		} else {
			f.Evidence = append(f.Evidence, Evidence{Label: h.code, Value: h.vendor + ", " + h.where})
		}
		if !known {
			unknown++
			continue
		}
		f.Evidence = append(f.Evidence, Evidence{Label: "Meaning", Value: entry.Cause})
		explained = append(explained, entry)
	}

	switch {
	case len(explained) == 0:
		f.Fix = lookUp
	case len(explained) == 1 && unknown == 0:
		f.Fix = explained[0].Fix
	default:
		fixes := make([]string, len(explained))
		for i, e := range explained {
			fixes[i] = fixFor(e)
		}
		f.Fix = strings.Join(fixes, " ")
		if unknown > 0 {
			f.Fix += " For the other codes: " + strings.ToLower(lookUp[:1]) + lookUp[1:]
		}
	}
	return f
}

// fixFor names the code a fix belongs to, for a finding with several.
func fixFor(e kb.Entry) string {
	if e.Code != "" {
		return e.Code + ": " + e.Fix
	}
	return e.Vendor + " message: " + e.Fix
}

// scannableBody returns up to maxBodyScan bytes of a response body that is
// worth searching: HTML, JSON, XML, or plain text. Scripts are skipped on
// purpose: IdP login pages ship JavaScript bundles that list every error
// code they might ever display, which would make every capture look broken.
func scannableBody(c *har.Content) string {
	mime := strings.ToLower(c.MimeType)
	if strings.Contains(mime, "javascript") || strings.Contains(mime, "ecmascript") {
		return ""
	}
	textual := strings.HasPrefix(mime, "text/") || strings.Contains(mime, "json") || strings.Contains(mime, "xml")
	if !textual || c.Text == "" {
		return ""
	}
	b, err := c.Bytes()
	if err != nil {
		return ""
	}
	if len(b) > maxBodyScan {
		b = b[:maxBodyScan]
	}
	return string(b)
}

// ErrorCodesInBody returns the IdP error codes and known messages in a
// response body, in the order found, without duplicates. It applies
// exactly the checks HAR004 applies to bodies, so the redactor can keep
// these when it removes a body and HAR004 still finds them in the redacted
// file.
func ErrorCodesInBody(c *har.Content) []string {
	body := scannableBody(c)
	if body == "" {
		return nil
	}
	var codes []string
	seen := map[string]bool{}
	for _, f := range findInBody(body, c.MimeType) {
		if !seen[f.code] {
			seen[f.code] = true
			codes = append(codes, f.code)
		}
	}
	return codes
}

// ErrorCodesInText returns the IdP error codes and known messages in text
// taken from a URL parameter such as error_description, under the rules
// HAR004 applies to URLs. The redactor keeps these when it removes the
// rest of the value.
func ErrorCodesInText(s string) []string {
	var out []found
	for _, p := range errorPatterns {
		for _, c := range p.re.FindAllString(s, -1) {
			out = append(out, found{c, p.vendor})
		}
	}
	if m := kbMatchers(); m.inURL != nil {
		for _, c := range m.inURL.FindAllString(s, -1) {
			out = append(out, found{c, m.vendor[c]})
		}
	}
	out = append(out, findMessages(s)...)
	var codes []string
	seen := map[string]bool{}
	for _, f := range out {
		if !seen[f.code] {
			seen[f.code] = true
			codes = append(codes, f.code)
		}
	}
	return codes
}

// FormatBodyCodes joins codes for a redacted body's placeholder so that
// findInBody finds every one of them again: a code with no vendor pattern
// is only recognized in a page as "Error: code", so it is written that way.
func FormatBodyCodes(codes []string) string {
	m := kbMatchers()
	parts := make([]string, len(codes))
	for i, c := range codes {
		if _, patternless := m.vendor[c]; patternless {
			parts[i] = "Error: " + c
		} else {
			parts[i] = c
		}
	}
	return strings.Join(parts, " ")
}

// IsOAuthError reports whether s is a standard OAuth 2.0 or OpenID Connect
// error value.
func IsOAuthError(s string) bool { return oauthErrors[s] }
