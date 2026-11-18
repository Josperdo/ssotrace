package main

import (
	"fmt"
	"net/http"
	"net/url"
)

// runSPA does what lab/sp/oidc.html does for one ?start= mode: build the
// authorization request, sign in, read the callback, and redeem the code
// from the "browser". Keep the two in step: the page is what a person
// clicks, this is the same thing scripted.
func runSPA(b *browser, mode string, acceptConsent bool) (string, error) {
	// The person opens the app first.
	if _, err := b.navigate(http.MethodGet, spaPage, nil); err != nil {
		return "", err
	}

	state, nonce, verifier := randomString(), randomString(), randomString()
	p := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {state},
		"nonce":         {nonce},
	}
	switch mode {
	case "implicit":
		p.Set("response_type", "id_token token")
	case "silent":
		p.Set("prompt", "none")
	}
	switch mode {
	case "plain":
		p.Set("code_challenge", verifier)
		p.Set("code_challenge_method", "plain")
	case "nopkce", "implicit":
	default:
		p.Set("code_challenge", s256(verifier))
		p.Set("code_challenge_method", "S256")
	}

	page, err := b.signIn(issuer+"/protocol/openid-connect/auth?"+p.Encode(), acceptConsent)
	if err != nil {
		return "", err
	}
	if page.url.Scheme+"://"+page.url.Host+page.url.Path != redirectURI {
		msg := pageError(page)
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d at %s", page.status, page.url.Path)
		}
		return "IdP page: " + msg, nil
	}

	params := page.url.Query()
	if b.fragment != "" {
		if params, err = url.ParseQuery(b.fragment); err != nil {
			return "", fmt.Errorf("parse fragment: %w", err)
		}
	}
	switch {
	case params.Get("state") != state:
		return "callback state differs from the request's", nil
	case params.Has("error"):
		return "callback error: " + params.Get("error"), nil
	case params.Has("id_token"):
		return "tokens in the fragment (implicit)", nil
	}

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {params.Get("code")},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
	}
	if mode == "wrongredirect" {
		form.Set("redirect_uri", redirectURI+"/")
	}
	if mode != "nopkce" && mode != "noverifier" {
		form.Set("code_verifier", verifier)
	}
	if mode == "secret" {
		form.Set("client_secret", "lab-not-a-secret")
	}
	status, err := b.redeem(form)
	if err != nil {
		return "", err
	}
	outcome := fmt.Sprintf("token endpoint HTTP %d", status)
	if mode == "twice" {
		again, err := b.redeem(form)
		if err != nil {
			return "", err
		}
		outcome += fmt.Sprintf(", then HTTP %d", again)
	}
	return outcome, nil
}
