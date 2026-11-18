package main

import (
	_ "embed"
	"net/http"
)

// oidcPage is the lab's single-page OIDC app. It is one static file: all
// of its OIDC logic runs in the browser, because the point is for the
// browser to make every request, the token request included, so a HAR
// captures the whole exchange.
//
//go:embed oidc.html
var oidcPage []byte

// oidcApp serves the SPA for both its start page and its callback; the
// page's script looks at the URL to decide what to do.
func (c config) oidcApp(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Always load the current page, so a stale copy never answers a
	// callback for a scenario it does not know.
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(oidcPage)
}
