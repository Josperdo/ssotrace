// Command oidcrun runs the lab's OIDC break scenarios against a running
// lab and checks what ssotrace reports for each.
//
// It plays the browser: it signs in as alice through Keycloak's real login
// pages, follows each redirect, redeems the code the way lab/sp/oidc.html
// does, and records everything as a HAR in lab/captures/oidcrun/. Admin
// changes (consent, redirect URIs, client type, keys) go through Keycloak's
// admin REST API and are undone after each scenario.
//
// What it cannot show is browser-only behavior, such as how a browser
// records a CORS-blocked response; that row stays a manual check.
//
// Usage, from the repository root, with the lab up and ssotrace built:
//
//	make lab-oidc
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"
)

const jwksURL = issuer + "/protocol/openid-connect/certs"

// scenario is one lab break: how to cause it and what ssotrace must
// report, as "RULE severity" entries.
type scenario struct {
	name   string
	mode   string                    // lab/sp/oidc.html ?start= mode
	change func(map[string]any)      // lab-spa client settings; nil = none
	accept bool                      // answer Yes on a consent screen
	rotate bool                      // sign with a newly added key
	args   func(dir string) []string // extra diagnose flags
	expect []string
	noFail bool // and no FAIL finding at all
}

func scenarios() []scenario {
	fetch := func(string) []string { return []string{"--fetch-jwks", jwksURL} }
	return []scenario{
		{name: "baseline", mode: "normal", accept: true, args: fetch, expect: []string{"OIDC009 pass"}, noFail: true},
		{name: "silent-no-session", mode: "silent", expect: []string{"OIDC001 info"}},
		{name: "consent-declined", mode: "normal", change: set("consentRequired", true), expect: []string{"OIDC001 fail"}},
		{
			name: "redirect-uri-not-registered", mode: "normal", accept: true,
			change: set("redirectUris", []string{"http://127.0.0.1:9999/*"}),
			expect: []string{"OIDC001 fail", "OIDC003 fail"},
		},
		{name: "redirect-uri-differs", mode: "wrongredirect", accept: true, expect: []string{"OIDC003 fail", "OIDC007 fail"}},
		{name: "code-redeemed-twice", mode: "twice", accept: true, expect: []string{"OIDC007 fail"}},
		{name: "pkce-verifier-missing", mode: "noverifier", accept: true, expect: []string{"OIDC007 fail"}},
		{name: "confidential-client", mode: "normal", accept: true, change: set("publicClient", false), expect: []string{"OIDC007 fail"}},
		{name: "no-pkce", mode: "nopkce", accept: true, expect: []string{"OIDC008 warn"}},
		{name: "pkce-plain", mode: "plain", accept: true, expect: []string{"OIDC008 warn"}},
		{name: "client-secret-in-browser", mode: "secret", accept: true, expect: []string{"OIDC008 warn"}},
		{name: "implicit-flow", mode: "implicit", accept: true, change: set("implicitFlowEnabled", true), expect: []string{"OIDC008 warn"}},
		{
			name: "rotated-key-old-jwks", mode: "normal", accept: true, rotate: true,
			args:   func(dir string) []string { return []string{"--jwks", filepath.Join(dir, "old-jwks.json")} },
			expect: []string{"OIDC009 info"},
		},
		{name: "rotated-key-live-jwks", mode: "normal", accept: true, rotate: true, args: fetch, expect: []string{"OIDC009 pass"}},
	}
}

func set(key string, v any) func(map[string]any) {
	return func(c map[string]any) { c[key] = v }
}

func main() {
	envPath := flag.String("env", "lab/.env", "lab settings file")
	outDir := flag.String("out", "lab/captures/oidcrun", "where to write the HARs")
	ssotrace := flag.String("ssotrace", "bin/ssotrace", "ssotrace binary to check")
	only := flag.String("run", "", "run only scenarios whose name contains this")
	flag.Parse()
	if err := run(*envPath, *outDir, *ssotrace, *only); err != nil {
		fmt.Fprintln(os.Stderr, "oidcrun:", err)
		os.Exit(1)
	}
}

func run(envPath, outDir, ssotrace, only string) error {
	env, err := readEnv(envPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(ssotrace); err != nil {
		return fmt.Errorf("ssotrace binary: %w (run make build)", err)
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", outDir, err)
	}
	adm, err := newAdmin(env["KC_BOOTSTRAP_ADMIN_USERNAME"], env["KC_BOOTSTRAP_ADMIN_PASSWORD"])
	if err != nil {
		return err
	}
	// The key set from before any rotation, for the rotated-key check.
	if err := saveJWKS(filepath.Join(outDir, "old-jwks.json")); err != nil {
		return err
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SCENARIO\tWHAT HAPPENED\tSSOTRACE\tRESULT")
	failed := 0
	for _, s := range scenarios() {
		if only != "" && !strings.Contains(s.name, only) {
			continue
		}
		outcome, verdict, ok, err := runOne(adm, env["LAB_USER_PASSWORD"], s, outDir, ssotrace)
		result := "ok"
		switch {
		case err != nil:
			result, verdict = "ERROR", err.Error()
			failed++
		case !ok:
			result = "MISMATCH (want " + strings.Join(s.expect, ", ") + ")"
			failed++
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.name, outcome, verdict, result)
	}
	_ = tw.Flush()
	fmt.Printf("\nHARs in %s\n", outDir)
	if failed > 0 {
		return fmt.Errorf("%d scenario(s) did not match", failed)
	}
	return nil
}

func runOne(adm *admin, password string, s scenario, outDir, ssotrace string) (outcome, verdict string, ok bool, err error) {
	b, err := newBrowser("alice", password)
	if err != nil {
		return "", "", false, err
	}
	var got findings
	// Diagnose inside the scenario, before its changes are undone:
	// --fetch-jwks must see the key set as it was when the token was
	// signed, rotated key included.
	step := func() error {
		if outcome, err = runSPA(b, s.mode, s.accept); err != nil {
			return err
		}
		harPath := filepath.Join(outDir, s.name+".har")
		if err := b.rec.write(harPath); err != nil {
			return err
		}
		var extra []string
		if s.args != nil {
			extra = s.args(outDir)
		}
		got, err = diagnose(ssotrace, harPath, extra)
		return err
	}
	if s.change != nil {
		inner := step
		step = func() error { return adm.withClient(s.change, inner) }
	}
	if s.rotate {
		inner := step
		step = func() error { return adm.withRotatedKey(inner) }
	}
	if err := step(); err != nil {
		return outcome, "", false, err
	}
	return outcome, strings.Join(got.notable(), ", "), got.matches(s), nil
}

// findings is what one ssotrace diagnose run reported.
type findings []struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
}

func diagnose(bin, harPath string, extra []string) (findings, error) {
	args := append([]string{"diagnose", harPath, "--format", "json"}, extra...)
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, args...) //nolint:gosec // the operator names the ssotrace binary to check
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// Exit code 1 only means "at least one FAIL"; the JSON says which.
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			return nil, fmt.Errorf("ssotrace diagnose: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
	}
	var rep struct {
		Findings findings `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		return nil, fmt.Errorf("read ssotrace JSON: %w", err)
	}
	return rep.Findings, nil
}

func (fs findings) has(rule, severity string) bool {
	for _, f := range fs {
		if f.RuleID == rule && f.Severity == severity {
			return true
		}
	}
	return false
}

func (fs findings) matches(s scenario) bool {
	for _, want := range s.expect {
		rule, sev, _ := strings.Cut(want, " ")
		if !fs.has(rule, sev) {
			return false
		}
	}
	return !s.noFail || !fs.anyFail()
}

func (fs findings) anyFail() bool {
	for _, f := range fs {
		if f.Severity == "fail" {
			return true
		}
	}
	return false
}

// notable lists the non-PASS findings, plus OIDC009's verdict, which is
// the point of the key scenarios even when it passes.
func (fs findings) notable() []string {
	var out []string
	for _, f := range fs {
		if f.Severity != "pass" || f.RuleID == "OIDC009" {
			out = append(out, f.RuleID+" "+f.Severity)
		}
	}
	if len(out) == 0 {
		return []string{"all pass"}
	}
	return out
}

func saveJWKS(path string) error {
	resp, err := http.Get(jwksURL) //nolint:gosec,noctx // fixed lab URL
	if err != nil {
		return fmt.Errorf("fetch lab keys: %w (is the lab up? make lab-up)", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch lab keys: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read lab keys: %w", err)
	}
	return os.WriteFile(path, b, 0o600)
}

// readEnv reads KEY=VALUE lines from lab/.env. Values are never printed.
func readEnv(path string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // the operator names the lab settings file
	if err != nil {
		return nil, fmt.Errorf("%w (cp lab/.env.example lab/.env)", err)
	}
	defer func() { _ = f.Close() }()
	env := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			env[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	for _, k := range []string{"KC_BOOTSTRAP_ADMIN_USERNAME", "KC_BOOTSTRAP_ADMIN_PASSWORD", "LAB_USER_PASSWORD"} {
		if env[k] == "" {
			return nil, fmt.Errorf("%s is not set in %s", k, path)
		}
	}
	return env, nil
}
