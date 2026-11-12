package diagnose

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Josperdo/ssotrace/internal/har"
)

// idpErrorCodes is HAR004: an identity provider's own error code appears in
// the capture. These codes are often the single most useful clue, and they
// are easy to miss in a long HAR: in a redirect URL's error_description,
// or buried in an error page.
//
// The rule reports the raw code and where it was found. It does not try to
// explain vendor codes; the vendor's documentation does that best.
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

// jsonError matches an "error" field in a JSON body, as token endpoints
// return it.
var jsonError = regexp.MustCompile(`"error"\s*:\s*"([a-z_]{1,40})"`)

// maxBodyScan caps how much of each response body is searched. Error codes
// appear near the top of error pages; scanning a 50 MB download for them
// would only waste time.
const maxBodyScan = 1 << 20

// maxCodesShown limits how many distinct codes are listed.
const maxCodesShown = 5

type codeHit struct {
	code, vendor, where string
}

func (idpErrorCodes) Check(ctx Context) []Finding {
	if ctx.HAR == nil || len(ctx.HAR.Log.Entries) == 0 {
		return nil
	}
	var hits []codeHit
	seen := map[string]bool{}
	add := func(code, vendor, where string) {
		if !seen[code] {
			seen[code] = true
			hits = append(hits, codeHit{code, vendor, where})
		}
	}

	for i := range ctx.HAR.Log.Entries {
		e := &ctx.HAR.Log.Entries[i]
		loc := fmt.Sprintf("entry %d: %s", i, describeRequest(&e.Request))

		for _, p := range errorPatterns {
			for _, c := range p.re.FindAllString(e.Request.URL, -1) {
				add(c, p.vendor, loc+" (URL)")
			}
			for _, c := range p.re.FindAllString(e.Response.RedirectURL, -1) {
				add(c, p.vendor, loc+" (redirect target)")
			}
		}
		if v, ok := e.Request.QueryParam("error"); ok && oauthErrors[v] {
			add(v, "OAuth 2.0 / OIDC", loc+" (URL)")
		}
		if v, ok := e.Request.FormParam("error"); ok && oauthErrors[v] {
			add(v, "OAuth 2.0 / OIDC", loc+" (form body)")
		}

		body := scannableBody(&e.Response.Content)
		if body == "" {
			continue
		}
		for _, p := range errorPatterns {
			for _, c := range p.re.FindAllString(body, -1) {
				add(c, p.vendor, loc+" (response body)")
			}
		}
		if strings.Contains(e.Response.Content.MimeType, "json") {
			for _, m := range jsonError.FindAllStringSubmatch(body, -1) {
				if oauthErrors[m[1]] {
					add(m[1], "OAuth 2.0 / OIDC", loc+" (response body)")
				}
			}
		}
	}

	if len(hits) == 0 {
		return []Finding{passFinding("HAR004", "No IdP error codes found",
			"No Microsoft Entra ID, AD FS, Okta, or OAuth error codes appear in URLs or response bodies.")}
	}

	f := Finding{
		RuleID:   "HAR004",
		Severity: Warn,
		Title:    "IdP error code found",
		Detail: fmt.Sprintf("The capture contains %s from the identity provider. The code usually names the exact problem, "+
			"even when the page the user saw was generic.", plural(len(hits), "error code")),
		Fix: "Look up the code in the identity provider's documentation, or search the IdP's sign-in logs for it at the time of the capture.",
	}
	for i, h := range hits {
		if i == maxCodesShown {
			f.Evidence = append(f.Evidence, Evidence{Label: "More codes", Value: fmt.Sprintf("%d not shown", len(hits)-maxCodesShown)})
			break
		}
		f.Evidence = append(f.Evidence, Evidence{Label: h.code, Value: h.vendor + ", " + h.where})
	}
	return []Finding{f}
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

// ErrorCodesInBody returns the IdP error codes in a response body, in the
// order found, without duplicates. It applies exactly the checks HAR004
// applies to bodies, so the redactor can keep these codes when it removes
// a body and HAR004 still finds them in the redacted file.
func ErrorCodesInBody(c *har.Content) []string {
	body := scannableBody(c)
	if body == "" {
		return nil
	}
	var codes []string
	seen := map[string]bool{}
	add := func(code string) {
		if !seen[code] {
			seen[code] = true
			codes = append(codes, code)
		}
	}
	for _, p := range errorPatterns {
		for _, code := range p.re.FindAllString(body, -1) {
			add(code)
		}
	}
	if strings.Contains(c.MimeType, "json") {
		for _, m := range jsonError.FindAllStringSubmatch(body, -1) {
			if oauthErrors[m[1]] {
				add(m[1])
			}
		}
	}
	return codes
}

// IsOAuthError reports whether s is a standard OAuth 2.0 or OpenID Connect
// error value.
func IsOAuthError(s string) bool { return oauthErrors[s] }
