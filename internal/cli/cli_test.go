package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	info := BuildInfo{Version: "v0.0.0-test", Commit: "abc1234", Date: "2026-01-01T00:00:00Z"}

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
			name:       "diagnose missing file",
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
			args:       []string{"diagnose", "x.har", "--format", "yaml"},
			wantCode:   ExitUsage,
			wantStderr: `invalid --format "yaml"`,
		},
		{
			name:       "diagnose unknown flag",
			args:       []string{"diagnose", "--bogus", "x.har"},
			wantCode:   ExitUsage,
			wantStderr: "flag provided but not defined: -bogus",
		},
		{
			name:       "diagnose flags before file",
			args:       []string{"diagnose", "--format", "json", "--no-color", "x.har"},
			wantCode:   ExitUsage,
			wantStderr: "diagnose: not implemented yet",
		},
		{
			name:       "diagnose flags after file",
			args:       []string{"diagnose", "x.har", "--format", "json"},
			wantCode:   ExitUsage,
			wantStderr: "diagnose: not implemented yet",
		},
		{
			name:       "diagnose flags on both sides of file",
			args:       []string{"diagnose", "--no-color", "x.har", "--format=markdown"},
			wantCode:   ExitUsage,
			wantStderr: "diagnose: not implemented yet",
		},
		{
			name:       "double dash makes dash-prefixed name a file",
			args:       []string{"diagnose", "--", "-weird.har"},
			wantCode:   ExitUsage,
			wantStderr: "diagnose: not implemented yet",
		},
		{
			name:       "diagnose -h prints usage to stdout",
			args:       []string{"diagnose", "-h"},
			wantCode:   ExitOK,
			wantStdout: "Usage:",
		},
		{
			name:       "redact missing -o",
			args:       []string{"redact", "in.har"},
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
			args:       []string{"redact", "in.har", "-o", "out.har"},
			wantCode:   ExitUsage,
			wantStderr: "redact: not implemented yet",
		},
		{
			name:       "scan missing file",
			args:       []string{"scan"},
			wantCode:   ExitUsage,
			wantStderr: "missing <file.har>",
		},
		{
			name:       "scan valid args",
			args:       []string{"scan", "x.har"},
			wantCode:   ExitUsage,
			wantStderr: "scan: not implemented yet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(tt.args, &stdout, &stderr, info)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			checkStream(t, "stdout", stdout.String(), tt.wantStdout)
			checkStream(t, "stderr", stderr.String(), tt.wantStderr)
		})
	}
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
