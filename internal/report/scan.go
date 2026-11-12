package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Josperdo/ssotrace/internal/redact"
)

// maxLeaksShown is how many examples of each kind the text report lists.
// The count is always complete; JSON lists every leak.
const maxLeaksShown = 5

// ScanText writes `ssotrace scan` results for a person. Values are shown
// only as previews (a short prefix and a length), so the report itself is
// safe to share even when the HAR is not.
func ScanText(w io.Writer, file string, leaks []redact.Leak, opts TextOptions) error {
	bw := bufio.NewWriter(w)
	t := textWriter{w: bw, color: opts.Color}

	t.line(t.style(ansiBold, "ssotrace scan · "+clean(file)))
	t.line("")
	if len(leaks) == 0 {
		t.line(t.style(ansiGreen, "✓ No secrets found.") + " ssotrace found no cookies, tokens, passwords, signatures, or email addresses.")
		return flush(bw, "scan")
	}

	noun := "secrets"
	if len(leaks) == 1 {
		noun = "secret"
	}
	t.line(t.style(ansiRed, fmt.Sprintf("✗ %d %s found.", len(leaks), noun)) + " Do not share this file as it is.")

	for _, kc := range redact.Summary(leaks) {
		t.line("")
		t.line(t.style(ansiBold, fmt.Sprintf("%s (%d)", kc.Kind, kc.Count)))
		var rows []redact.Leak
		for _, l := range leaks {
			if l.Kind == kc.Kind {
				rows = append(rows, l)
			}
		}
		width := 0
		for i, l := range rows {
			if i == maxLeaksShown {
				break
			}
			width = max(width, len([]rune(clean(l.Where))))
		}
		for i, l := range rows {
			if i == maxLeaksShown {
				t.line(t.style(ansiDim, fmt.Sprintf("  … %d more", len(rows)-maxLeaksShown)))
				break
			}
			where := clean(l.Where)
			gap := strings.Repeat(" ", width-len([]rune(where))+2)
			t.line(fmt.Sprintf("  %s  %s%s%s", t.style(ansiDim, fmt.Sprintf("entry %-3d", l.Entry)), where, gap, clean(l.Preview)))
		}
	}

	t.line("")
	t.line(t.style(ansiBold, "→ ") + "Make a shareable copy with: ssotrace redact " + clean(file) + " -o " + clean(redactedName(file)))
	return flush(bw, "scan")
}

// ScanJSON writes scan results for scripts.
func ScanJSON(w io.Writer, file, version string, leaks []redact.Leak) error {
	if leaks == nil {
		leaks = []redact.Leak{}
	}
	doc := struct {
		SchemaVersion int                `json:"schema_version"`
		Version       string             `json:"ssotrace_version,omitempty"`
		File          string             `json:"file"`
		Summary       []redact.KindCount `json:"summary"`
		Leaks         []redact.Leak      `json:"leaks"`
	}{SchemaVersion, version, file, redact.Summary(leaks), leaks}
	if doc.Summary == nil {
		doc.Summary = []redact.KindCount{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("write json scan: %w", err)
	}
	return nil
}

// redactedName suggests an output name: login.har → login.redacted.har.
func redactedName(file string) string {
	if strings.HasSuffix(strings.ToLower(file), ".har") {
		return file[:len(file)-4] + ".redacted.har"
	}
	return file + ".redacted.har"
}

func flush(bw *bufio.Writer, what string) error {
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("write %s report: %w", what, err)
	}
	return nil
}
