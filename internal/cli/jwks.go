package cli

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Josperdo/ssotrace/internal/oidc"
)

// loadJWKS reads a JWK Set file (--jwks).
func loadJWKS(path string) (*oidc.KeySet, error) {
	f, err := os.Open(path) //nolint:gosec // the user names the file to read; that is the point of the flag
	if err != nil {
		return nil, fmt.Errorf("--jwks: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, oidc.MaxJWKS+1))
	if err != nil {
		return nil, fmt.Errorf("--jwks: read %s: %w", path, err)
	}
	ks, err := oidc.ParseJWKS(data)
	if err != nil {
		return nil, fmt.Errorf("--jwks: %s: %w", path, err)
	}
	return ks, nil
}

// fetchTimeout bounds the whole --fetch-jwks request, redirects included.
const fetchTimeout = 15 * time.Second

// maxFetchRedirects is enough for an http-to-canonical-host hop or two.
const maxFetchRedirects = 3

// fetchJWKS downloads a JWK Set from the URL the user gave (--fetch-jwks).
//
// This is ssotrace's only network call, and it goes only where the user
// typed: the URL is never taken from the capture, because a hostile HAR
// could then choose what ssotrace connects to and learn that its file was
// opened. Nothing about the capture is sent.
func fetchJWKS(rawURL, version string) (*oidc.KeySet, error) {
	if err := checkFetchURL(rawURL); err != nil {
		return nil, fmt.Errorf("--fetch-jwks: %w", err)
	}
	client := &http.Client{Timeout: fetchTimeout, CheckRedirect: checkFetchRedirect}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("--fetch-jwks: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ssotrace/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("--fetch-jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		// The body is not shown: it is whatever the server chose to say.
		return nil, fmt.Errorf("--fetch-jwks: server answered HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, oidc.MaxJWKS+1))
	if err != nil {
		return nil, fmt.Errorf("--fetch-jwks: read response: %w", err)
	}
	ks, err := oidc.ParseJWKS(data)
	if err != nil {
		return nil, fmt.Errorf("--fetch-jwks: %w", err)
	}
	return ks, nil
}

// checkFetchURL allows https anywhere and plain http only to this machine,
// where a local test IdP usually runs without TLS. Over plain http to
// another host, anyone on the network path could swap in their own keys
// and make forged tokens "verify".
func checkFetchURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("not an absolute URL")
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && isLoopback(u.Hostname()):
		return nil
	default:
		return fmt.Errorf("URL must use https (plain http is allowed only for localhost), got %q", u.Scheme)
	}
}

// checkFetchRedirect is the redirect policy for --fetch-jwks. A redirect
// must meet the same rule as the URL the user typed, and once on https it
// must stay on https: otherwise a server the user chose could point the
// fetch at a plain-http service on this machine.
func checkFetchRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxFetchRedirects {
		return errors.New("too many redirects")
	}
	if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("refusing a redirect from https to plain http")
	}
	return checkFetchURL(req.URL.String())
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// mergeKeySets combines the keys from --jwks and --fetch-jwks.
func mergeKeySets(sets ...*oidc.KeySet) *oidc.KeySet {
	var out *oidc.KeySet
	for _, s := range sets {
		if s == nil {
			continue
		}
		if out == nil {
			out = &oidc.KeySet{}
		}
		out.Keys = append(out.Keys, s.Keys...)
		out.Skipped += s.Skipped
	}
	return out
}
