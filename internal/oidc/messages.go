package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/Josperdo/ssotrace/internal/secret"
)

// Lookup returns the first value of a named parameter and whether it was
// present. Callers adapt it to wherever the parameters were found (query
// string, form body, URL fragment), so this package never needs to know
// about HAR files.
type Lookup func(name string) (string, bool)

// ValuesLookup adapts url.Values to a Lookup.
func ValuesLookup(v url.Values) Lookup {
	return func(name string) (string, bool) {
		vs, ok := v[name]
		if !ok || len(vs) == 0 {
			return "", false
		}
		return vs[0], true
	}
}

// AuthorizationRequest is the browser's trip to the authorization endpoint
// (RFC 6749 §4.1.1, OIDC Core §3.1.2.1).
//
// Values that bind the login to one browser session (state, nonce) are kept
// for comparison but serialized only as previews or presence flags.
type AuthorizationRequest struct {
	ClientID            string `json:"client_id"`
	ResponseType        string `json:"response_type"`
	ResponseMode        string `json:"response_mode,omitempty"`
	Prompt              string `json:"prompt,omitempty"`
	RedirectURI         string `json:"redirect_uri,omitempty"` // query dropped
	Scope               string `json:"scope,omitempty"`
	StatePreview        string `json:"state_preview,omitempty"`
	HasNonce            bool   `json:"has_nonce"`
	HasCodeChallenge    bool   `json:"has_code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`

	State string `json:"-"`
	Nonce string `json:"-"`
}

// OpenID reports whether this is an OpenID Connect request rather than
// plain OAuth 2.0: OIDC Core §3.1.2.1 requires the "openid" scope.
func (a *AuthorizationRequest) OpenID() bool {
	return slices.Contains(strings.Fields(a.Scope), "openid")
}

// ParseAuthorizationRequest reads an authorization request's parameters.
// It never fails: a request missing parameters is still a request, and
// spotting what is missing is the rules' job.
func ParseAuthorizationRequest(get Lookup) *AuthorizationRequest {
	a := &AuthorizationRequest{}
	a.ClientID, _ = get("client_id")
	a.ResponseType, _ = get("response_type")
	a.ResponseMode, _ = get("response_mode")
	a.Prompt, _ = get("prompt")
	a.Scope, _ = get("scope")
	if v, ok := get("redirect_uri"); ok {
		a.RedirectURI = StripQuery(v)
	}
	a.State, _ = get("state")
	a.StatePreview = preview(a.State)
	a.Nonce, a.HasNonce = get("nonce")
	_, a.HasCodeChallenge = get("code_challenge")
	a.CodeChallengeMethod, _ = get("code_challenge_method")
	return a
}

// Callback is the authorization server's answer, delivered to the
// redirect_uri (RFC 6749 §4.1.2 and §4.1.2.1, OIDC Core §3.2.2.5).
type Callback struct {
	StatePreview     string `json:"state_preview,omitempty"`
	CodePreview      string `json:"code_preview,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	// Issuer is the RFC 9207 "iss" parameter, which some servers add to
	// defend against mix-up attacks.
	Issuer         string `json:"iss,omitempty"`
	IDToken        *JWT   `json:"id_token,omitempty"`
	IDTokenError   string `json:"id_token_error,omitempty"`
	HasAccessToken bool   `json:"has_access_token,omitempty"`

	State string `json:"-"`
	// Code is kept only to pair the callback with the token request that
	// redeems it. An authorization code is a short-lived credential.
	Code string `json:"-"`
}

// ParseCallback reads a callback's parameters.
func ParseCallback(get Lookup) *Callback {
	c := &Callback{}
	c.State, _ = get("state")
	c.StatePreview = preview(c.State)
	c.Code, _ = get("code")
	c.CodePreview = preview(c.Code)
	c.Error, _ = get("error")
	c.ErrorDescription, _ = get("error_description")
	c.ErrorURI, _ = get("error_uri")
	c.Issuer, _ = get("iss")
	_, c.HasAccessToken = get("access_token")
	if v, ok := get("id_token"); ok {
		c.IDToken, c.IDTokenError = parseToken(v)
	}
	return c
}

// TokenRequest is a token endpoint call the browser made itself, as
// single-page apps using PKCE do (RFC 6749 §4.1.3, RFC 7636 §4.5).
type TokenRequest struct {
	GrantType       string `json:"grant_type"`
	ClientID        string `json:"client_id,omitempty"`
	RedirectURI     string `json:"redirect_uri,omitempty"` // query dropped
	CodePreview     string `json:"code_preview,omitempty"`
	HasCodeVerifier bool   `json:"has_code_verifier"`
	// HasClientSecret means the browser sent a client secret, which then
	// is not secret: anyone using the app can read it.
	HasClientSecret bool `json:"has_client_secret,omitempty"`

	Code string `json:"-"`
}

// ParseTokenRequest reads a token request's form parameters.
func ParseTokenRequest(get Lookup) *TokenRequest {
	t := &TokenRequest{}
	t.GrantType, _ = get("grant_type")
	t.ClientID, _ = get("client_id")
	if v, ok := get("redirect_uri"); ok {
		t.RedirectURI = StripQuery(v)
	}
	t.Code, _ = get("code")
	t.CodePreview = preview(t.Code)
	_, t.HasCodeVerifier = get("code_verifier")
	_, t.HasClientSecret = get("client_secret")
	return t
}

// TokenResponse is the token endpoint's JSON answer (RFC 6749 §5.1 for
// success, §5.2 for errors).
type TokenResponse struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IDToken          *JWT   `json:"id_token,omitempty"`
	IDTokenError     string `json:"id_token_error,omitempty"`
	// AccessToken is set only when the access token is itself a JWT.
	// Opaque access tokens are normal and carry nothing to check.
	AccessToken     *JWT `json:"access_token,omitempty"`
	HasAccessToken  bool `json:"has_access_token"`
	HasRefreshToken bool `json:"has_refresh_token,omitempty"`
}

// MaxTokenResponse bounds the token response body Parse will decode. Real
// ones are a few kilobytes.
const MaxTokenResponse = 1 << 20

// ParseTokenResponse decodes a token endpoint response body. Errors never
// quote the body: it may hold live tokens.
func ParseTokenResponse(body []byte) (*TokenResponse, error) {
	if len(body) > MaxTokenResponse {
		return nil, fmt.Errorf("token response is %d bytes, over the %d-byte limit", len(body), MaxTokenResponse)
	}
	var w struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ErrorURI         string `json:"error_uri"`
		TokenType        string `json:"token_type"`
		Scope            string `json:"scope"`
		IDToken          string `json:"id_token"`
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
	}
	if err := unmarshalObject(body, &w); err != nil {
		return nil, fmt.Errorf("token response: %w", err)
	}
	r := &TokenResponse{
		Error:            w.Error,
		ErrorDescription: w.ErrorDescription,
		ErrorURI:         w.ErrorURI,
		TokenType:        w.TokenType,
		Scope:            w.Scope,
		HasAccessToken:   w.AccessToken != "",
		HasRefreshToken:  w.RefreshToken != "",
	}
	if w.IDToken != "" {
		r.IDToken, r.IDTokenError = parseToken(w.IDToken)
	}
	if strings.Count(w.AccessToken, ".") == 2 {
		r.AccessToken, _ = Parse(w.AccessToken) // not a JWT after all: treat as opaque
	}
	return r, nil
}

// parseToken parses a token that must be a JWT (an ID token), returning
// the reason as text when it cannot be read.
func parseToken(v string) (*JWT, string) {
	t, err := Parse(v)
	if err != nil {
		return nil, err.Error()
	}
	return t, ""
}

// StripQuery keeps scheme, host, and path. Query strings and fragments are
// where codes and tokens travel, so they never go into the model.
func StripQuery(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + u.Path
}

func preview(s string) string {
	if s == "" {
		return ""
	}
	return secret.Preview(s)
}

// ErrNotCallback is returned by FragmentParams when a URL fragment
// carries no authorization response.
var ErrNotCallback = errors.New("fragment carries no authorization response")

// FragmentParams reads the parameters of an authorization response
// delivered in a URL fragment (response_mode=fragment, and the implicit
// flow). Browsers never send fragments to servers, so the only place a
// capture shows them is the Location header of the redirect that set them.
func FragmentParams(rawURL string) (url.Values, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, ErrNotCallback
	}
	v, _ := url.ParseQuery(u.EscapedFragment()) // keep well-formed pairs; see har.QueryParam
	for _, name := range []string{"code", "id_token", "access_token", "error"} {
		if v.Has(name) {
			return v, nil
		}
	}
	return nil, ErrNotCallback
}
