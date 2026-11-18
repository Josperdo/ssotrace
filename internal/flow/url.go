package flow

import (
	"net/url"
	"strings"
)

// SameURL compares two endpoint URLs the way a strict receiver does:
// scheme and host case-insensitively, default ports dropped, path exactly,
// query and fragment ignored. SAML rules use it for Destination and
// Recipient; OIDC pairing uses it to match a callback to its redirect_uri.
func SameURL(a, b string) bool {
	na, okA := normalizeURL(a)
	nb, okB := normalizeURL(b)
	return okA && okB && na == nb
}

func normalizeURL(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, true
}
