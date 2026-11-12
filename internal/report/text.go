package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/Josperdo/ssotrace/internal/diagnose"
)

// TextOptions controls the human-readable renderer.
type TextOptions struct {
	// Color enables ANSI colors. The CLI turns it on only for a terminal,
	// and never with --no-color or the NO_COLOR environment variable.
	Color bool
}

const (
	textWidth  = 80 // wrap prose at a width every terminal can show
	bodyIndent = 10 // detail, evidence, and fix line up under the title
)

// ANSI styles. Each is wrapped with its reset by style().
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[1;31m"
	ansiYellow = "\x1b[1;33m"
	ansiCyan   = "\x1b[36m"
	ansiGreen  = "\x1b[32m"
)

// Text writes the report for a person reading a terminal. It is built to
// be understood in five seconds: problems first, grouped by login attempt,
// each with its evidence and fix; passing checks collapse into one count.
//
//   - FAIL shows the explanation, the evidence, and the fix.
//   - WARN shows the evidence and the fix.
//   - INFO shows only the title and the fix.
func Text(w io.Writer, r *Report, opts TextOptions) error {
	bw := bufio.NewWriter(w)
	t := textWriter{w: bw, color: opts.Color}

	t.line(t.style(ansiBold, "ssotrace · "+clean(r.File)))
	t.line(t.style(ansiDim, r.loginCount()))

	for _, s := range r.sections() {
		t.line("")
		t.line(t.style(ansiBold, clean(s.Title)))
		if len(s.Findings) == 0 {
			t.line("  " + t.style(ansiGreen, "✓") + " no problems found")
			continue
		}
		for _, f := range s.Findings {
			t.finding(f)
		}
	}

	c := r.counts()
	t.line("")
	result := summaryLine(c)
	switch {
	case c.Fail > 0:
		result = t.style(ansiRed, result)
	case c.Warn > 0:
		result = t.style(ansiYellow, result)
	default:
		result = t.style(ansiGreen, result)
	}
	t.line("Result: " + result)
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("write text report: %w", err)
	}
	return nil
}

type textWriter struct {
	w     *bufio.Writer
	color bool
}

func (t textWriter) line(s string) {
	_, _ = t.w.WriteString(s + "\n")
}

func (t textWriter) style(code, s string) string {
	if !t.color {
		return s
	}
	return code + s + ansiReset
}

var severityStyle = map[diagnose.Severity]struct{ mark, label, code string }{
	diagnose.Fail: {"✗", "FAIL", ansiRed},
	diagnose.Warn: {"!", "WARN", ansiYellow},
	diagnose.Info: {"i", "INFO", ansiCyan},
}

func (t textWriter) finding(f diagnose.Finding) {
	st := severityStyle[f.Severity]
	// "  ✗ FAIL  SAML002  Title": mark and label colored, rule ID dimmed so
	// the eye lands on the title.
	// Pad before styling: the escape codes are invisible but would count
	// toward the width, so colored labels would lose their alignment.
	head := fmt.Sprintf("  %s %s %s  %s",
		t.style(st.code, st.mark), t.style(st.code, fmt.Sprintf("%-5s", st.label)), t.style(ansiDim, f.RuleID), clean(f.Title))
	t.line(head)

	pad := strings.Repeat(" ", bodyIndent)
	if f.Severity == diagnose.Fail && f.Detail != "" {
		for _, l := range wrap(clean(f.Detail), textWidth-bodyIndent) {
			t.line(pad + l)
		}
	}
	if f.Severity != diagnose.Info && len(f.Evidence) > 0 {
		width := 0
		for _, e := range f.Evidence {
			width = max(width, utf8.RuneCountInString(clean(e.Label)))
		}
		for _, e := range f.Evidence {
			label := clean(e.Label)
			gap := strings.Repeat(" ", width-utf8.RuneCountInString(label)+2)
			t.line(pad + t.style(ansiDim, label) + gap + clean(e.Value))
		}
	}
	if f.Fix != "" {
		lines := wrap(clean(f.Fix), textWidth-bodyIndent-2)
		for i, l := range lines {
			prefix := "  "
			if i == 0 {
				prefix = t.style(ansiBold, "→ ")
			}
			t.line(pad + prefix + l)
		}
	}
}

// wrap breaks s into lines of at most width runes at spaces. A single word
// longer than width (a long URL) gets a line of its own rather than being
// cut, so it can still be copied.
func wrap(s string, width int) []string {
	var lines []string
	var cur strings.Builder
	n := 0
	for _, word := range strings.Fields(s) {
		wl := utf8.RuneCountInString(word)
		if n > 0 && n+1+wl > width {
			lines = append(lines, cur.String())
			cur.Reset()
			n = 0
		}
		if n > 0 {
			cur.WriteByte(' ')
			n++
		}
		cur.WriteString(word)
		n += wl
	}
	if n > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}
