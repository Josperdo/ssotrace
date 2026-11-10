package diagnose

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/Josperdo/ssotrace/internal/flow"
	"github.com/Josperdo/ssotrace/internal/har"
)

// noSSOTraffic is HAR001: the capture contains no SAML or OIDC messages,
// so nothing else can be diagnosed. This is almost always a capture
// problem, not an SSO problem, and the fix says how to capture again.
type noSSOTraffic struct{}

func (noSSOTraffic) ID() string { return "HAR001" }

// maxHostsShown keeps the evidence readable on captures with hundreds of
// third-party hosts.
const maxHostsShown = 5

func (noSSOTraffic) Check(ctx Context) []Finding {
	if ctx.HAR == nil {
		return nil
	}
	entries := ctx.HAR.Log.Entries

	var saml, oidc int
	for i := range entries {
		switch flow.Detect(&entries[i]) {
		case flow.SAML:
			saml++
		case flow.OIDC:
			oidc++
		}
	}

	if saml+oidc > 0 {
		return []Finding{{
			RuleID:   "HAR001",
			Severity: Pass,
			Title:    "SSO traffic found",
			Detail:   fmt.Sprintf("Found %d SAML and %d OAuth/OIDC requests.", saml, oidc),
		}}
	}

	f := Finding{
		RuleID:   "HAR001",
		Severity: Fail,
		Title:    "No SSO traffic found",
		Fix:      `Capture the sign-in again. In the browser's developer tools, open the Network tab and turn on "Preserve log" (Firefox: "Persist Logs") before you start. Then begin the sign-in from the very start, ideally in a private window, and export the HAR once you see the error.`,
		Evidence: []Evidence{{Label: "Requests in capture", Value: fmt.Sprint(len(entries))}},
	}
	if len(entries) == 0 {
		f.Detail = "The HAR file contains no requests at all. The capture was probably started after the page loaded, or exported from an empty Network tab."
		return []Finding{f}
	}
	f.Detail = fmt.Sprintf("None of the %d requests carries a SAML message or an OAuth/OIDC authorization request, callback, or token request. "+
		"Usually the log was cleared by a redirect (Preserve log was off) or recording started after the SSO exchange had already happened.", len(entries))
	if hosts := hostsSummary(entries); hosts != "" {
		f.Evidence = append(f.Evidence, Evidence{Label: "Hosts in capture", Value: hosts})
	}
	return []Finding{f}
}

// hostsSummary lists the distinct hosts in the capture, which tells the
// reader at a glance whether the identity provider appears at all. Only
// u.Host is used: it never includes the "user:password@" part of a URL,
// the path, or the query string, any of which could hold a secret.
func hostsSummary(entries []har.Entry) string {
	seen := make(map[string]bool)
	for i := range entries {
		u, err := url.Parse(entries[i].Request.URL)
		if err != nil || u.Host == "" {
			continue
		}
		seen[u.Host] = true
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts) // map order is random; sorted output is stable

	if len(hosts) > maxHostsShown {
		more := len(hosts) - maxHostsShown
		return strings.Join(hosts[:maxHostsShown], ", ") + fmt.Sprintf(" (+%d more)", more)
	}
	return strings.Join(hosts, ", ")
}
