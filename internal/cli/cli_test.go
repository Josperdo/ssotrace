package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Josperdo/ssotrace/internal/testutil"
)

// Placeholders in test args, replaced with real temp file paths.
const (
	validHAR     = "{valid}"     // a minimal, well-formed HAR
	malformedHAR = "{malformed}" // a JSON file that is not a HAR
	missingHAR   = "{missing}"   // a path that does not exist
)

func TestRun(t *testing.T) {
	info := BuildInfo{Version: "v0.0.0-test", Commit: "abc1234", Date: "2026-01-01T00:00:00Z"}

	dir := t.TempDir()
	paths := map[string]string{
		validHAR:     writeFile(t, dir, "valid.har", `{"log":{"version":"1.2","entries":[]}}`),
		malformedHAR: writeFile(t, dir, "malformed.har", `{"not":"a har"}`),
		missingHAR:   filepath.Join(dir, "missing.har"),
	}

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string // substring; "" means stdout must be empty
		wantStderr string // substring; "" means stderr must be empty
	}{
		{
			name:       "no args prints usage",
			args:       nil,
			wantCode:   ExitOK,
			wantStdout: "Usage:",
		},
		{
			name:       "help",
			args:       []string{"help"},
			wantCode:   ExitOK,
			wantStdout: "Usage:",
		},
		{
			name:       "version",
			args:       []string{"version"},
			wantCode:   ExitOK,
			wantStdout: "ssotrace v0.0.0-test (commit abc1234, built 2026-01-01T00:00:00Z)",
		},
		{
			name:       "unknown command",
			args:       []string{"frobnicate"},
			wantCode:   ExitUsage,
			wantStderr: `unknown command "frobnicate"`,
		},
		{
			name:       "diagnose missing file arg",
			args:       []string{"diagnose"},
			wantCode:   ExitUsage,
			wantStderr: "missing <file.har>",
		},
		{
			name:       "diagnose too many files",
			args:       []string{"diagnose", "a.har", "b.har"},
			wantCode:   ExitUsage,
			wantStderr: "expected one <file.har> argument, got 2",
		},
		{
			name:       "diagnose bad format",
			args:       []string{"diagnose", validHAR, "--format", "yaml"},
			wantCode:   ExitUsage,
			wantStderr: `invalid --format "yaml"`,
		},
		{
			name:       "diagnose unknown flag",
			args:       []string{"diagnose", "--bogus", validHAR},
			wantCode:   ExitUsage,
			wantStderr: "flag provided but not defined: -bogus",
		},
		{
			name:       "diagnose flags before file",
			args:       []string{"diagnose", "--format", "json", "--no-color", validHAR},
			wantCode:   ExitFail, // empty capture: HAR001 fails
			wantStdout: `"schema_version": 1`,
		},
		{
			name:       "diagnose flags after file",
			args:       []string{"diagnose", validHAR, "--format", "json"},
			wantCode:   ExitFail,
			wantStdout: `"rule_id": "HAR001"`,
		},
		{
			name:       "diagnose flags on both sides of file",
			args:       []string{"diagnose", "--no-color", validHAR, "--format=markdown"},
			wantCode:   ExitFail,
			wantStdout: "## ssotrace report: valid.har",
		},
		{
			name:       "diagnose text is the default",
			args:       []string{"diagnose", validHAR},
			wantCode:   ExitFail,
			wantStdout: "Result: 1 failure",
		},
		{
			name:       "diagnose clock skew accepted",
			args:       []string{"diagnose", validHAR, "--format", "json", "--clock-skew", "90s"},
			wantCode:   ExitFail,
			wantStdout: `"schema_version": 1`,
		},
		{
			name:       "diagnose clock skew negative",
			args:       []string{"diagnose", validHAR, "--clock-skew", "-1m"},
			wantCode:   ExitUsage,
			wantStderr: "between 0 and 1h",
		},
		{
			name:       "diagnose clock skew too large",
			args:       []string{"diagnose", validHAR, "--clock-skew", "5h"},
			wantCode:   ExitUsage,
			wantStderr: "between 0 and 1h",
		},
		{
			name:       "diagnose clock skew not a duration",
			args:       []string{"diagnose", validHAR, "--clock-skew", "5"},
			wantCode:   ExitUsage,
			wantStderr: "invalid value",
		},
		{
			name:       "double dash makes dash-prefixed name a file",
			args:       []string{"diagnose", "--", "-weird.har"},
			wantCode:   ExitUsage,
			wantStderr: "-weird.har: no such file",
		},
		{
			name:       "diagnose -h prints usage to stdout",
			args:       []string{"diagnose", "-h"},
			wantCode:   ExitOK,
			wantStdout: "Usage:",
		},
		{
			name:       "diagnose nonexistent file",
			args:       []string{"diagnose", missingHAR},
			wantCode:   ExitUsage,
			wantStderr: "no such file",
		},
		{
			name:       "diagnose malformed file",
			args:       []string{"diagnose", malformedHAR},
			wantCode:   ExitUsage,
			wantStderr: `not a HAR file: missing "log" object`,
		},
		{
			name:       "diagnose file over --max-size",
			args:       []string{"diagnose", validHAR, "--max-size", "1B"},
			wantCode:   ExitUsage,
			wantStderr: "raise the limit with --max-size",
		},
		{
			name:       "diagnose bad --max-size",
			args:       []string{"diagnose", validHAR, "--max-size", "512MB"},
			wantCode:   ExitUsage,
			wantStderr: `invalid size "512MB"`,
		},
		{
			name:       "redact missing -o",
			args:       []string{"redact", validHAR},
			wantCode:   ExitUsage,
			wantStderr: "-o <out.har> is required",
		},
		{
			name:       "redact refuses to overwrite input",
			args:       []string{"redact", "in.har", "-o", "./in.har"},
			wantCode:   ExitUsage,
			wantStderr: "must not be the input file",
		},
		{
			name:       "redact valid args",
			args:       []string{"redact", validHAR, "-o", "out.har"},
			wantCode:   ExitUsage,
			wantStderr: "redact: not implemented yet",
		},
		{
			name:       "redact malformed input",
			args:       []string{"redact", malformedHAR, "-o", "out.har"},
			wantCode:   ExitUsage,
			wantStderr: "not a HAR file",
		},
		{
			name:       "scan missing file arg",
			args:       []string{"scan"},
			wantCode:   ExitUsage,
			wantStderr: "missing <file.har>",
		},
		{
			name:       "scan valid args",
			args:       []string{"scan", validHAR},
			wantCode:   ExitOK, // an empty capture holds no secrets
			wantStdout: "No secrets found",
		},
		{
			name:       "scan json",
			args:       []string{"scan", validHAR, "--format", "json"},
			wantCode:   ExitOK,
			wantStdout: `"leaks": []`,
		},
		{
			name:       "scan bad format",
			args:       []string{"scan", validHAR, "--format", "markdown"},
			wantCode:   ExitUsage,
			wantStderr: "want text or json",
		},
		{
			name:       "scan nonexistent file",
			args:       []string{"scan", missingHAR},
			wantCode:   ExitUsage,
			wantStderr: "no such file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := make([]string, len(tt.args))
			for i, a := range tt.args {
				if p, ok := paths[a]; ok {
					a = p
				}
				args[i] = a
			}

			var stdout, stderr bytes.Buffer
			code := Run(args, &stdout, &stderr, info)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			checkStream(t, "stdout", stdout.String(), tt.wantStdout)
			checkStream(t, "stderr", stderr.String(), tt.wantStderr)
		})
	}
}

// TestLoadErrorIsNotUsage: a bad file is an input problem, so the user gets
// the reason, not a wall of usage text about flags they typed correctly.
func TestLoadErrorIsNotUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	Run([]string{"scan", filepath.Join(t.TempDir(), "missing.har")}, &stdout, &stderr, BuildInfo{})
	if strings.Contains(stderr.String(), "Usage:") {
		t.Errorf("load error printed usage:\n%s", stderr.String())
	}
}

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"1024", 1024, false},
		{"1B", 1, false},
		{"512MiB", 512 << 20, false},
		{"512mib", 512 << 20, false},
		{"1 GiB", 1 << 30, false},
		{"64KiB", 64 << 10, false},
		{"512MB", 0, true}, // decimal units are refused, not guessed
		{"0", 0, true},
		{"-5MiB", 0, true},
		{"1.5GiB", 0, true},
		{"lots", 0, true},
		{"", 0, true},
		{"99999999999999GiB", 0, true}, // overflows int64
	}
	for _, tt := range tests {
		got, err := parseByteSize(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseByteSize(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("parseByteSize(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func checkStream(t *testing.T, name, got, want string) {
	t.Helper()
	if want == "" {
		if got != "" {
			t.Errorf("%s = %q, want empty", name, got)
		}
		return
	}
	if !strings.Contains(got, want) {
		t.Errorf("%s = %q, want it to contain %q", name, got, want)
	}
}

// TestDiagnoseJSONSAMLFlow runs the whole pipeline on a generated, signed
// SP-initiated login and checks the flow model in the JSON output.
func TestDiagnoseJSONSAMLFlow(t *testing.T) {
	login := testutil.NewSAMLLogin(t, testutil.DefaultAuthnRequestOptions(), testutil.DefaultResponseOptions())
	path := writeFile(t, t.TempDir(), "login.har", string(testutil.MarshalHAR(t, login.HAR)))

	var stdout, stderr bytes.Buffer
	code := Run([]string{"diagnose", path, "--format", "json"}, &stdout, &stderr, BuildInfo{})
	if code != ExitOK {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}

	var out struct {
		SchemaVersion int `json:"schema_version"`
		SAML          struct {
			Flows []struct {
				Request  struct{ Binding string } `json:"request"`
				Response struct {
					Binding string
					Message struct {
						Response struct {
							Assertions []struct {
								Verified bool
								Subject  struct {
									NameID struct{ Value string } `json:"name_id"`
								}
							}
						}
					}
				} `json:"response"`
				IDPInitiated bool `json:"idp_initiated"`
			}
		}
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if out.SchemaVersion != 1 || len(out.SAML.Flows) != 1 {
		t.Fatalf("schema %d, flows %d", out.SchemaVersion, len(out.SAML.Flows))
	}
	f := out.SAML.Flows[0]
	if f.Request.Binding != "HTTP-Redirect" || f.Response.Binding != "HTTP-POST" || f.IDPInitiated {
		t.Errorf("flow = %+v", f)
	}
	as := f.Response.Message.Response.Assertions
	if len(as) != 1 || !as[0].Verified || as[0].Subject.NameID.Value != "alice@example.com" {
		t.Errorf("assertions = %+v", as)
	}
}

// TestDiagnoseExitCodes runs the real pipeline on generated SAML logins in
// every output format: a clean login exits 0, a broken one exits 1, and
// the format never changes the exit code.
func TestDiagnoseExitCodes(t *testing.T) {
	dir := t.TempDir()
	good := testutil.NewSAMLLogin(t, testutil.DefaultAuthnRequestOptions(), testutil.DefaultResponseOptions())
	badResp := testutil.DefaultResponseOptions()
	badResp.SignAssertion = false // SAML007 FAIL
	bad := testutil.NewSAMLLogin(t, testutil.DefaultAuthnRequestOptions(), badResp)

	goodPath := writeFile(t, dir, "good.har", string(testutil.MarshalHAR(t, good.HAR)))
	badPath := writeFile(t, dir, "bad.har", string(testutil.MarshalHAR(t, bad.HAR)))

	for _, format := range []string{"text", "json", "markdown"} {
		for _, tc := range []struct {
			path string
			want int
		}{{goodPath, ExitOK}, {badPath, ExitFail}} {
			var stdout, stderr bytes.Buffer
			code := Run([]string{"diagnose", tc.path, "--format", format}, &stdout, &stderr, BuildInfo{Version: "test"})
			if code != tc.want {
				t.Errorf("%s %s: exit %d, want %d (stderr %q)", format, filepath.Base(tc.path), code, tc.want, stderr.String())
			}
			if stdout.Len() == 0 {
				t.Errorf("%s %s: no output", format, filepath.Base(tc.path))
			}
		}
	}
}

func TestUseColor(t *testing.T) {
	// A buffer is never a terminal, whatever the settings.
	var buf bytes.Buffer
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")
	if useColor(false, &buf) {
		t.Error("color enabled for a non-terminal writer")
	}

	// A regular file is not a terminal either: output redirected to a
	// file must stay free of escape codes.
	f, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if useColor(false, f) {
		t.Error("color enabled for a regular file")
	}

	// The opt-outs win before the terminal check is even made.
	for _, tc := range []struct {
		name, noColor, term string
		flag                bool
	}{
		{"--no-color", "", "xterm", true},
		{"NO_COLOR set", "1", "xterm", false},
		{"TERM=dumb", "", "dumb", false},
	} {
		t.Setenv("NO_COLOR", tc.noColor)
		t.Setenv("TERM", tc.term)
		if useColor(tc.flag, os.Stdout) {
			t.Errorf("%s: color enabled", tc.name)
		}
	}
}

// TestScanFindsSecrets: a generated SAML login holds a signature and a
// NameID, so scan exits 1 and lists them without printing the values.
func TestScanFindsSecrets(t *testing.T) {
	login := testutil.NewSAMLLogin(t, testutil.DefaultAuthnRequestOptions(), testutil.DefaultResponseOptions())
	path := writeFile(t, t.TempDir(), "login.har", string(testutil.MarshalHAR(t, login.HAR)))

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"scan", path}, &stdout, &stderr, BuildInfo{}); code != ExitFail {
		t.Fatalf("exit %d, want %d (stderr %q)", code, ExitFail, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"secrets found", "SignatureValue", "NameID", "ssotrace redact login.har -o login.redacted.har"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "alice@example.com") {
		t.Error("scan output contains the user's email address")
	}
}
