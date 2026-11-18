package testutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/Josperdo/ssotrace/internal/har"
)

// SignJWT returns a compact RS256 JWT carrying claims, signed with key and
// labeled with kid.
func SignJWT(t testing.TB, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal JWT segment: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}) + "." + enc(claims)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// OIDCLoginOptions describes a synthetic authorization code login. Each
// field is something a break scenario changes.
type OIDCLoginOptions struct {
	Issuer      string
	ClientID    string
	RedirectURI string
	State       string // sent in the authorization request; "" sends none
	// CallbackState is the state the callback returns. It defaults to
	// State; set it to test a mismatch.
	CallbackState *string
	Nonce         string
	Code          string
	// TokenCode is the code the token request redeems. It defaults to Code.
	TokenCode *string
	Delivery  string // "query" (default), "form_post", or "fragment"
	PKCE      bool
	// Error makes the callback an error response instead of delivering a
	// code; no token call follows.
	Error            string
	ErrorDescription string
	TokenStatus      int    // defaults to 200
	TokenBody        string // overrides the generated token response body
	// IDTokenClaims replace or add claims in the ID token; a nil value
	// removes the claim.
	IDTokenClaims map[string]any
	Started       time.Time // when the authorization request was sent
	// Prompt is sent as the prompt parameter, e.g. "none" for silent sign-in.
	Prompt string
	// ResponseType defaults to "code".
	ResponseType string
	// IDP signs the ID token; nil generates a fresh key.
	IDP *KeyPair
	// TokenRedirectURI is the redirect_uri the token request sends. It
	// defaults to RedirectURI.
	TokenRedirectURI *string
	// ChallengeMethod is the PKCE code_challenge_method; "-" sends none.
	// It defaults to S256.
	ChallengeMethod string
	// OmitCodeVerifier drops the code_verifier from the token request.
	OmitCodeVerifier bool
	// ClientSecret, if set, is sent by the browser in the token request.
	ClientSecret string
	// Reloads appends that many reloads of the callback page after the
	// token call: each sends the same callback again, and the page tries
	// to redeem the same code, which the IdP refuses with invalid_grant.
	// It applies to query and form_post delivery only, because reloading
	// a fragment callback sends no new request.
	Reloads int
}

// DefaultOIDCLoginOptions returns a valid public-client login with PKCE,
// started at RefTime.
func DefaultOIDCLoginOptions() OIDCLoginOptions {
	return OIDCLoginOptions{
		Issuer:      "https://idp.example.com/realms/lab",
		ClientID:    "web-app",
		RedirectURI: "https://app.example.org/callback",
		State:       "st-4f1c2a9e7b3d4c5e",
		Nonce:       "nonce-8a7b6c5d4e3f2a1b",
		Code:        "code-0123456789abcdef0123",
		Delivery:    "query",
		PKCE:        true,
		Started:     RefTime,
	}
}

// OIDCLogin is a synthetic login as a browser would record it.
type OIDCLogin struct {
	HAR     *har.HAR
	Key     *KeyPair // signed the ID token
	IDToken string
}

// NewOIDCLogin builds the browser's view of an authorization code login:
//  1. GET to the authorization endpoint,
//  2. the callback, delivered as the options say, and
//  3. the SPA's own POST to the token endpoint.
func NewOIDCLogin(t testing.TB, o OIDCLoginOptions) *OIDCLogin {
	t.Helper()
	idp := o.IDP
	if idp == nil {
		idp = NewKeyPair(t, "idp.example.com")
	}
	at := o.Started
	responseType := o.ResponseType
	if responseType == "" {
		responseType = "code"
	}

	auth := url.Values{
		"client_id":     {o.ClientID},
		"response_type": {responseType},
		"redirect_uri":  {o.RedirectURI},
		"scope":         {"openid profile"},
	}
	if o.State != "" {
		auth.Set("state", o.State)
	}
	if o.Nonce != "" {
		auth.Set("nonce", o.Nonce)
	}
	if o.Prompt != "" {
		auth.Set("prompt", o.Prompt)
	}
	if o.PKCE {
		auth.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
		switch o.ChallengeMethod {
		case "":
			auth.Set("code_challenge_method", "S256")
		case "-":
		default:
			auth.Set("code_challenge_method", o.ChallengeMethod)
		}
	}
	if o.Delivery != "" && o.Delivery != "query" {
		auth.Set("response_mode", o.Delivery)
	}
	entries := []har.Entry{GetEntry(t, o.Issuer+"/protocol/openid-connect/auth?"+auth.Encode(), at, 200)}

	cbState := o.State
	if o.CallbackState != nil {
		cbState = *o.CallbackState
	}
	cb := url.Values{}
	if cbState != "" {
		cb.Set("state", cbState)
	}
	if o.Error != "" {
		cb.Set("error", o.Error)
		if o.ErrorDescription != "" {
			cb.Set("error_description", o.ErrorDescription)
		}
	} else {
		cb.Set("code", o.Code)
	}
	cbAt := at.Add(10 * time.Second)
	switch o.Delivery {
	case "form_post":
		entries = append(entries, PostFormEntry(o.RedirectURI, cb, cbAt, 302))
	case "fragment":
		// The IdP's login form answers with a redirect whose fragment
		// carries the response; the browser then loads the bare URL.
		login := PostFormEntry(o.Issuer+"/login-actions/authenticate", url.Values{"username": {"user"}}, cbAt, 302)
		login.Response.Headers = append(login.Response.Headers, har.NameValue{Name: "Location", Value: o.RedirectURI + "#" + cb.Encode()})
		login.Response.RedirectURL = o.RedirectURI + "#" + cb.Encode()
		entries = append(entries, login, GetEntry(t, o.RedirectURI, cbAt.Add(time.Second), 200))
	default:
		entries = append(entries, GetEntry(t, o.RedirectURI+"?"+cb.Encode(), cbAt, 200))
	}

	login := &OIDCLogin{Key: idp}
	if o.Error == "" {
		tokenAt := cbAt.Add(2 * time.Second)
		claims := map[string]any{
			"iss":   o.Issuer,
			"sub":   "00000000-0000-4000-8000-000000000001",
			"aud":   o.ClientID,
			"azp":   o.ClientID,
			"iat":   tokenAt.Unix(),
			"exp":   tokenAt.Add(5 * time.Minute).Unix(),
			"nonce": o.Nonce,
		}
		for k, v := range o.IDTokenClaims {
			if v == nil {
				delete(claims, k)
			} else {
				claims[k] = v
			}
		}
		login.IDToken = SignJWT(t, idp.Key, "lab-key-1", claims)

		code := o.Code
		if o.TokenCode != nil {
			code = *o.TokenCode
		}
		form := url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {code},
			"redirect_uri": {o.RedirectURI},
			"client_id":    {o.ClientID},
		}
		if o.TokenRedirectURI != nil {
			form.Set("redirect_uri", *o.TokenRedirectURI)
		}
		if o.ClientSecret != "" {
			form.Set("client_secret", o.ClientSecret)
		}
		if o.PKCE && !o.OmitCodeVerifier {
			form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
		}
		status := o.TokenStatus
		if status == 0 {
			status = 200
		}
		body := o.TokenBody
		if body == "" {
			b, _ := json.Marshal(map[string]any{ //nolint:gosec // synthetic fixture tokens, not credentials
				"access_token":  "opaque-access-token-0123456789",
				"refresh_token": "opaque-refresh-token-0123456789",
				"id_token":      login.IDToken,
				"token_type":    "Bearer",
				"expires_in":    300,
			})
			body = string(b)
		}
		tok := PostFormEntry(o.Issuer+"/protocol/openid-connect/token", form, tokenAt, status)
		tok.Response.Content = har.Content{Size: int64(len(body)), MimeType: "application/json", Text: body}
		entries = append(entries, tok)

		if o.Delivery != "fragment" {
			callback := entries[1]
			refused := `{"error":"invalid_grant","error_description":"Code not valid"}`
			for i := 1; i <= o.Reloads; i++ {
				again := tokenAt.Add(time.Duration(i) * time.Minute)
				cbAgain := callback
				cbAgain.StartedDateTime = again.UTC().Format(time.RFC3339Nano)
				tokAgain := PostFormEntry(o.Issuer+"/protocol/openid-connect/token", form, again.Add(time.Second), 400)
				tokAgain.Response.Content = har.Content{Size: int64(len(refused)), MimeType: "application/json", Text: refused}
				entries = append(entries, cbAgain, tokAgain)
			}
		}
	}
	login.HAR = NewHAR(entries...)
	return login
}

// Ptr returns a pointer to v, for optional fixture fields.
func Ptr[T any](v T) *T { return &v }

// RSAJWKS returns a JWK Set document holding pub under kid, as an IdP's
// jwks_uri would serve it.
func RSAJWKS(t testing.TB, kid string, pub *rsa.PublicKey) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	return b
}
