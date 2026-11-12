// Package cli dispatches ssotrace subcommands and parses their flags.
//
// Run never touches os.Args, os.Stdout, or os.Exit directly. Everything comes
// in as arguments and goes out as a return code, so the whole CLI surface is
// testable with in-memory buffers.
package cli

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Josperdo/ssotrace/internal/diagnose"
	"github.com/Josperdo/ssotrace/internal/flow"
	"github.com/Josperdo/ssotrace/internal/har"
	"github.com/Josperdo/ssotrace/internal/report"
)

// Exit codes are part of the public contract: scripts and CI jobs branch on
// them, so they must stay stable.
const (
	ExitOK    = 0 // no FAIL findings
	ExitFail  = 1 // at least one FAIL finding
	ExitUsage = 2 // usage or input error
)

// BuildInfo identifies the running binary. main fills it from link-time
// variables or the Go toolchain's embedded build metadata.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

const usageText = `ssotrace diagnoses failed SSO logins from a HAR file and redacts it so it is safe to share.

Usage:
  ssotrace diagnose <file.har> [--format text|json|markdown] [--no-color] [--max-size SIZE]
                    [--clock-skew DURATION] [--idp-cert FILE] [--sp-entity-id ID]
  ssotrace redact   <file.har> -o <out.har> [--max-size SIZE]
  ssotrace scan     <file.har> [--max-size SIZE]
  ssotrace version
  ssotrace help

Options:
  --format FORMAT          text (default), json for scripts, or markdown for tickets
  --no-color               plain text output; colors are only used on a terminal,
                           and NO_COLOR=1 also turns them off
  --max-size SIZE          largest HAR file to read, e.g. 512MiB or 1GiB (default 256MiB)
  --clock-skew DURATION    how far apart IdP and SP clocks may be before a time
                           check fails, e.g. 90s or 5m (default 3m)
  --idp-cert FILE          PEM file with the IdP signing certificate(s) you trust;
                           without it, signatures prove integrity, not who signed
  --sp-entity-id ID        the SP's entity ID, used to check the audience when the
                           capture has no AuthnRequest (IdP-initiated logins)

Exit codes:
  0  no FAIL findings
  1  at least one FAIL finding
  2  usage or input error
`

// Run executes the subcommand named in args (os.Args[1:]) and returns the
// process exit code.
func Run(args []string, stdout, stderr io.Writer, info BuildInfo) int {
	if len(args) == 0 {
		writeUsage(stdout)
		return ExitOK
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help", "-h", "-help", "--help":
		writeUsage(stdout)
		return ExitOK
	case "version", "--version":
		_, _ = fmt.Fprintf(stdout, "ssotrace %s (commit %s, built %s)\n", info.Version, info.Commit, info.Date)
		return ExitOK
	case "diagnose":
		return runDiagnose(rest, stdout, stderr, info)
	case "redact":
		return runRedact(rest, stdout, stderr)
	case "scan":
		return runScan(rest, stdout, stderr)
	default:
		return usageError(stderr, fmt.Sprintf("unknown command %q", cmd))
	}
}

func runDiagnose(args []string, stdout, stderr io.Writer, info BuildInfo) int {
	fs := newFlagSet("diagnose")
	format := fs.String("format", "text", "output format: text, json, or markdown")
	noColor := fs.Bool("no-color", false, "disable colored output")
	skew := fs.Duration("clock-skew", diagnose.DefaultClockSkew, "how far apart IdP and SP clocks may be, e.g. 90s or 5m")
	idpCert := fs.String("idp-cert", "", "PEM file with the IdP signing certificate(s) you trust")
	spEntityID := fs.String("sp-entity-id", "", "the SP's entity ID, for checking IdP-initiated logins")
	maxSize := addMaxSizeFlag(fs)

	pos, code, done := parse(fs, args, stdout, stderr)
	if done {
		return code
	}
	if code, ok := requireOneFile("diagnose", pos, stderr); !ok {
		return code
	}
	// An hour of "tolerance" would hide every real clock problem; past that
	// the flag is more likely a typo (5h for 5m) than a wish.
	if *skew < 0 || *skew > time.Hour {
		return usageError(stderr, fmt.Sprintf("diagnose: --clock-skew must be between 0 and 1h, got %v", *skew))
	}
	switch *format {
	case "text", "json", "markdown":
	default:
		return usageError(stderr, fmt.Sprintf("diagnose: invalid --format %q (want text, json, or markdown)", *format))
	}
	var certs []*x509.Certificate
	if *idpCert != "" {
		var err error
		if certs, err = loadCerts(*idpCert); err != nil {
			_, _ = fmt.Fprintf(stderr, "ssotrace: %v\n", err)
			return ExitUsage
		}
	}
	h, ok := loadHAR(pos[0], int64(*maxSize), stderr)
	if !ok {
		return ExitUsage
	}
	reg, err := diagnose.DefaultRules()
	if err != nil {
		// A broken built-in registry is a programming error, not bad input;
		// report it plainly rather than panicking.
		_, _ = fmt.Fprintf(stderr, "ssotrace: %v\n", err)
		return ExitUsage
	}
	ctx := diagnose.Context{
		HAR:        h,
		SAML:       flow.TraceSAML(h),
		ClockSkew:  *skew,
		IDPCerts:   certs,
		SPEntityID: strings.TrimSpace(*spEntityID),
	}
	findings := diagnose.Run(ctx, reg)
	rep := &report.Report{
		File:     filepath.Base(pos[0]),
		Version:  info.Version,
		Findings: findings,
		SAML:     ctx.SAML,
	}
	switch *format {
	case "json":
		err = report.JSON(stdout, rep)
	case "markdown":
		err = report.Markdown(stdout, rep)
	default:
		err = report.Text(stdout, rep, report.TextOptions{Color: useColor(*noColor, stdout)})
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ssotrace: %v\n", err)
		return ExitUsage
	}
	if diagnose.HasFailures(findings) {
		return ExitFail
	}
	return ExitOK
}

func runRedact(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("redact")
	out := fs.String("o", "", "path for the redacted HAR (required)")
	maxSize := addMaxSizeFlag(fs)

	pos, code, done := parse(fs, args, stdout, stderr)
	if done {
		return code
	}
	if code, ok := requireOneFile("redact", pos, stderr); !ok {
		return code
	}
	if *out == "" {
		return usageError(stderr, "redact: -o <out.har> is required")
	}
	// The input file is evidence; overwriting it would destroy the only
	// unredacted copy. This catches the obvious case early. The real write
	// path will also compare file identity, which handles symlinks.
	if samePath(pos[0], *out) {
		return usageError(stderr, "redact: -o must not be the input file")
	}
	if _, ok := loadHAR(pos[0], int64(*maxSize), stderr); !ok {
		return ExitUsage
	}
	return notImplemented(stderr, "redact")
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("scan")
	maxSize := addMaxSizeFlag(fs)

	pos, code, done := parse(fs, args, stdout, stderr)
	if done {
		return code
	}
	if code, ok := requireOneFile("scan", pos, stderr); !ok {
		return code
	}
	if _, ok := loadHAR(pos[0], int64(*maxSize), stderr); !ok {
		return ExitUsage
	}
	return notImplemented(stderr, "scan")
}

// loadHAR loads path and reports any failure as an input error. Usage is
// not printed: the command line was fine, the file was not.
func loadHAR(path string, maxBytes int64, stderr io.Writer) (*har.HAR, bool) {
	h, err := har.Load(path, maxBytes)
	if err == nil {
		return h, true
	}
	// har.Load errors already start with the path (or "open <path>").
	_, _ = fmt.Fprintf(stderr, "ssotrace: %v\n", err)
	if errors.Is(err, har.ErrTooLarge) {
		_, _ = fmt.Fprintln(stderr, "If this file is really a HAR export, raise the limit with --max-size, e.g. --max-size 1GiB.")
	}
	return nil, false
}

func addMaxSizeFlag(fs *flag.FlagSet) *byteSize {
	size := byteSize(har.DefaultMaxBytes)
	fs.Var(&size, "max-size", "largest HAR file to read, e.g. 512MiB")
	return &size
}

// newFlagSet returns a FlagSet that reports errors to us instead of printing
// or exiting, so we control exactly what goes to stdout and stderr.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parse runs parseInterspersed and turns flag errors into exit codes.
// When done is true the caller must return code immediately.
func parse(fs *flag.FlagSet, args []string, stdout, stderr io.Writer) (pos []string, code int, done bool) {
	pos, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		// The user asked for help, so it is normal output, not an error.
		writeUsage(stdout)
		return nil, ExitOK, true
	}
	if err != nil {
		return nil, usageError(stderr, fmt.Sprintf("%s: %v", fs.Name(), err)), true
	}
	return pos, 0, false
}

// parseInterspersed lets flags appear before or after positional arguments.
//
// The standard flag package stops at the first non-flag argument, so
// `diagnose file.har --format json` would treat "--format" and "json" as
// positionals. We parse, move the first leftover argument to the positional
// list, and parse the remainder again until nothing is left.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		consumed := len(args) - len(rest)
		// "--" means "everything after this is positional", even values that
		// start with a dash. flag.Parse already consumed it; honor it here too.
		if consumed > 0 && args[consumed-1] == "--" {
			return append(positional, rest...), nil
		}
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func requireOneFile(cmd string, pos []string, stderr io.Writer) (int, bool) {
	switch len(pos) {
	case 1:
		return 0, true
	case 0:
		return usageError(stderr, cmd+": missing <file.har> argument"), false
	default:
		return usageError(stderr, fmt.Sprintf("%s: expected one <file.har> argument, got %d", cmd, len(pos))), false
	}
}

func samePath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		// Can't prove they differ, so treat them as the same (fail closed).
		return true
	}
	return absA == absB
}

func usageError(stderr io.Writer, msg string) int {
	_, _ = fmt.Fprintf(stderr, "ssotrace: %s\n\n", msg)
	writeUsage(stderr)
	return ExitUsage
}

func notImplemented(stderr io.Writer, cmd string) int {
	_, _ = fmt.Fprintf(stderr, "%s: not implemented yet\n", cmd)
	return ExitUsage
}

func writeUsage(w io.Writer) {
	_, _ = io.WriteString(w, usageText)
}

// useColor decides whether text output gets ANSI colors. Color is for
// people, so it is off whenever output is not a terminal (a pipe, a file,
// CI logs), and whenever the user opts out with --no-color, the NO_COLOR
// convention (https://no-color.org: any non-empty value), or TERM=dumb.
func useColor(noColor bool, w io.Writer) bool {
	if noColor || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	// Only a real *os.File can be a terminal; tests pass buffers.
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	// A character device is a terminal; a pipe or regular file is not.
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
