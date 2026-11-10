package diagnose

import (
	"fmt"
	"net/url"

	"github.com/Josperdo/ssotrace/internal/har"
)

// missingRequestBodies is HAR002: requests that sent a body have no body in
// the HAR. SAML responses (HTTP-POST binding), form_post callbacks, and
// token requests all travel in request bodies, so a capture without them
// hides exactly the messages ssotrace needs.
type missingRequestBodies struct{}

func (missingRequestBodies) ID() string { return "HAR002" }

// maxExamplesShown limits how many affected requests are listed.
const maxExamplesShown = 3

func (missingRequestBodies) Check(ctx Context) []Finding {
	if ctx.HAR == nil {
		return nil
	}

	var sent int         // requests whose bodySize says a body was sent
	var missing []string // method + host + path of those with nothing captured
	for i := range ctx.HAR.Log.Entries {
		r := &ctx.HAR.Log.Entries[i].Request
		// bodySize > 0 is the only reliable evidence that a body existed.
		// 0 means no body, and -1 means unknown; flagging unknowns would
		// warn about every exporter that doesn't measure sizes.
		if r.BodySize <= 0 {
			continue
		}
		sent++
		if !bodyCaptured(r.PostData) {
			missing = append(missing, describeRequest(r))
		}
	}

	if len(missing) == 0 {
		return []Finding{{
			RuleID:   "HAR002",
			Severity: Pass,
			Title:    "Request bodies captured",
			Detail:   fmt.Sprintf("All %d requests that sent a body have it in the capture.", sent),
		}}
	}

	f := Finding{
		RuleID:   "HAR002",
		Severity: Warn,
		Title:    "Request bodies missing",
		Detail: fmt.Sprintf("%d of %d requests sent a body, but the HAR does not contain it. "+
			"SAML responses, form_post callbacks, and token requests are sent as request bodies, so ssotrace cannot check them in this file. "+
			"This usually means the file passed through a HAR sanitizer or redaction tool, or the browser did not record request content.", len(missing), sent),
		Fix: "Export the HAR again directly from the browser's developer tools and run ssotrace on that original file. " +
			"To share it safely afterwards, use `ssotrace redact`, which keeps the SSO messages needed for diagnosis.",
		Evidence: []Evidence{{Label: "Requests without a captured body", Value: fmt.Sprintf("%d of %d", len(missing), sent)}},
	}
	for i, m := range missing {
		if i == maxExamplesShown {
			break
		}
		f.Evidence = append(f.Evidence, Evidence{Label: "Example", Value: m})
	}
	return []Finding{f}
}

func bodyCaptured(p *har.PostData) bool {
	return p != nil && (p.Text != "" || len(p.Params) > 0)
}

// describeRequest renders "POST https://host/path" without the query string,
// which can carry codes or tokens.
func describeRequest(r *har.Request) string {
	u, err := url.Parse(r.URL)
	if err != nil {
		return r.Method + " (unparseable URL)"
	}
	return fmt.Sprintf("%s %s://%s%s", r.Method, u.Scheme, u.Host, u.Path)
}
