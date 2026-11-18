package diagnose

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Josperdo/ssotrace/internal/flow"
	"github.com/Josperdo/ssotrace/internal/har"
	"github.com/Josperdo/ssotrace/internal/oidc"
	"github.com/Josperdo/ssotrace/internal/testutil"
)

// tokenAt is when the default fixture's token request is sent: the
// authorization request at RefTime, the callback 10s later, the token
// call 2s after that.
var tokenAt = testutil.RefTime.Add(12 * time.Second)

// oidcCase is one capture for an OIDC rule test.
type oidcCase struct {
	name   string
	edit   func(*testutil.OIDCLoginOptions)
	har    func(*har.HAR) // edit the capture after it is built
	keys   bool           // supply the fixture IdP's key set (--jwks)
	want   []string       // "severity title-substring", in order; nil = no findings
	reason string         // why this case exists, when the name is not enough
}

func oidcCtx(t *testing.T, c oidcCase) Context {
	t.Helper()
	o := testutil.DefaultOIDCLoginOptions()
	o.IDP = testIDP(t)
	if c.edit != nil {
		c.edit(&o)
	}
	h := testutil.NewOIDCLogin(t, o).HAR
	if c.har != nil {
		c.har(h)
	}
	ctx := Context{HAR: h, OIDC: flow.TraceOIDC(h), ClockSkew: DefaultClockSkew}
	if c.keys {
		ks, err := oidc.ParseJWKS(testutil.RSAJWKS(t, "lab-key-1", &testIDP(t).Key.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		ctx.JWKS = ks
	}
	return ctx
}

func runOIDCCases(t *testing.T, rule Rule, cases []oidcCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rule.Check(oidcCtx(t, c))
			if len(got) != len(c.want) {
				t.Fatalf("got %d findings, want %d: %s", len(got), len(c.want), describe(got))
			}
			for i, w := range c.want {
				sev, title, _ := strings.Cut(w, " ")
				if got[i].Severity.String() != sev || !strings.Contains(got[i].Title, title) {
					t.Errorf("finding %d = %s %q, want %s %q", i, got[i].Severity, got[i].Title, sev, title)
				}
				if got[i].RuleID != rule.ID() {
					t.Errorf("finding %d has rule ID %s", i, got[i].RuleID)
				}
				if got[i].Severity != Pass && got[i].Fix == "" {
					t.Errorf("finding %d has no fix text", i)
				}
				if got[i].Flow != nil {
					t.Errorf("finding %d points into the SAML flows", i)
				}
			}
		})
	}
}

func describe(fs []Finding) string {
	var parts []string
	for _, f := range fs {
		parts = append(parts, f.Severity.String()+" "+f.Title)
	}
	return strings.Join(parts, "; ")
}

// onlyAuthorization keeps the first entry (the authorization request) and
// answers it with status and an HTML body: the IdP showed an error page
// and never sent the browser back.
func onlyAuthorization(status int, body string) func(*har.HAR) {
	return func(h *har.HAR) {
		e := h.Log.Entries[0]
		e.Response.Status = status
		e.Response.Content = har.Content{MimeType: "text/html", Text: body}
		h.Log.Entries = []har.Entry{e}
	}
}

// rawToken builds a JWT with any header and an arbitrary signature, for
// tokens the fixture key cannot produce (alg none, HS256).
func rawToken(header string, claims map[string]any, sig string) string {
	b, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc(b) + "." + sig
}

func tokenBody(idToken string) string {
	b, _ := json.Marshal(map[string]any{"access_token": "opaque-at-0123456789", "id_token": idToken, "token_type": "Bearer"})
	return string(b)
}

func defaultClaims() map[string]any {
	return map[string]any{"iss": "https://idp.example.com/realms/lab", "aud": "web-app", "exp": tokenAt.Add(5 * time.Minute).Unix(), "nonce": "nonce-8a7b6c5d4e3f2a1b"}
}

func TestOIDC001CallbackError(t *testing.T) {
	runOIDCCases(t, callbackError{}, []oidcCase{
		{name: "success", want: []string{"pass Authorization server returned no errors"}},
		{
			name: "access denied",
			edit: func(o *testutil.OIDCLoginOptions) {
				o.Error, o.ErrorDescription = "access_denied", "User is not assigned"
			},
			want: []string{"fail Authorization server returned an error (access_denied)"},
		},
		{
			name: "silent sign-in needs the user",
			edit: func(o *testutil.OIDCLoginOptions) { o.Prompt, o.Error = "none", "login_required" },
			want: []string{"info Silent sign-in needs the user"},
		},
		{
			name:   "login_required without prompt=none",
			edit:   func(o *testutil.OIDCLoginOptions) { o.Error = "login_required" },
			want:   []string{"fail Authorization server returned an error (login_required)"},
			reason: "outside silent sign-in the error does block the user",
		},
		{
			name: "request rejected with an error page",
			har:  onlyAuthorization(400, "<p>We are sorry...</p>"),
			want: []string{"fail Authorization server rejected the request"},
		},
		{
			name: "request answered, no callback yet",
			har:  onlyAuthorization(200, "<form>sign in</form>"),
			want: nil,
		},
	})
}

func TestOIDC002StateMismatch(t *testing.T) {
	runOIDCCases(t, stateMismatch{}, []oidcCase{
		{name: "match", want: []string{"pass State matches"}},
		{
			name: "different state",
			edit: func(o *testutil.OIDCLoginOptions) { o.CallbackState = testutil.Ptr("st-from-another-tab-99") },
			want: []string{"fail State does not match"},
		},
		{
			name: "state dropped",
			edit: func(o *testutil.OIDCLoginOptions) { o.CallbackState = testutil.Ptr("") },
			want: []string{"fail State does not match"},
		},
		{
			name: "request not captured",
			har:  func(h *har.HAR) { h.Log.Entries = h.Log.Entries[1:] },
			want: []string{"info State could not be checked"},
		},
		{name: "no state sent or returned", edit: func(o *testutil.OIDCLoginOptions) { o.State = "" }, want: nil},
		{
			name:   "callback reloaded",
			edit:   func(o *testutil.OIDCLoginOptions) { o.Reloads = 2 },
			want:   []string{"pass State matches"},
			reason: "a reload repeats a callback whose state was already checked; it must not read as an incomplete capture",
		},
	})
}

func TestOIDC003RedirectURI(t *testing.T) {
	runOIDCCases(t, redirectURIMismatch{}, []oidcCase{
		{name: "accepted", want: []string{"pass redirect_uri accepted"}},
		{
			name: "keycloak error page",
			har:  onlyAuthorization(400, "<html><p>Invalid parameter: redirect_uri</p></html>"),
			want: []string{"fail IdP rejected the redirect_uri"},
		},
		{
			name: "token request sends another redirect_uri",
			edit: func(o *testutil.OIDCLoginOptions) {
				o.TokenRedirectURI = testutil.Ptr("https://app.example.org/callback/")
			},
			want: []string{"fail redirect_uri differs between authorization and token requests"},
		},
		{
			name: "token request omits redirect_uri",
			edit: func(o *testutil.OIDCLoginOptions) { o.TokenRedirectURI = testutil.Ptr("") },
			want: []string{"fail redirect_uri differs between authorization and token requests"},
		},
		{
			name: "token endpoint complaint with matching URIs is OIDC007's",
			edit: func(o *testutil.OIDCLoginOptions) {
				o.TokenStatus, o.TokenBody = 400, `{"error":"invalid_grant","error_description":"Incorrect redirect_uri"}`
			},
			want:   []string{"pass redirect_uri accepted"},
			reason: "\"not registered\" is claimed only at the authorization step",
		},
	})
}

func TestRedirectURIErrorPattern(t *testing.T) {
	tests := map[string]bool{
		"Invalid parameter: redirect_uri":  true, // Keycloak
		"Incorrect redirect_uri":           true, // Keycloak token endpoint
		"Error 400: redirect_uri_mismatch": true, // Google
		"The 'redirect_uri' parameter must be a Login redirect URI in the client app settings":       true, // Okta
		"AADSTS50011: The redirect URI specified in the request does not match":                      true, // Entra
		"The redirect URL is not registered for this client":                                         true,
		"<input name=\"redirect_uri\" value=\"https://app.example.org/cb\"><p>must be signed in</p>": false, // across tags
		"Sign in to continue": false,
	}
	for s, want := range tests {
		if got := redirectURIError.MatchString(s); got != want {
			t.Errorf("match(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestOIDC004Nonce(t *testing.T) {
	runOIDCCases(t, nonceMismatch{}, []oidcCase{
		{name: "match", want: []string{"pass ID token nonce matches"}},
		{
			name: "different nonce",
			edit: func(o *testutil.OIDCLoginOptions) {
				o.IDTokenClaims = map[string]any{"nonce": "nonce-of-another-sign-in"}
			},
			want: []string{"fail ID token nonce does not match"},
		},
		{
			name: "nonce missing from token",
			edit: func(o *testutil.OIDCLoginOptions) { o.IDTokenClaims = map[string]any{"nonce": nil} },
			want: []string{"fail ID token has no nonce"},
		},
		{name: "no nonce sent", edit: func(o *testutil.OIDCLoginOptions) { o.Nonce = "" }, want: nil},
	})
}

func TestOIDC005Audience(t *testing.T) {
	runOIDCCases(t, audienceNotClient{}, []oidcCase{
		{name: "match", want: []string{"pass ID token audience matches the client"}},
		{
			name: "other audience",
			edit: func(o *testutil.OIDCLoginOptions) {
				o.IDTokenClaims = map[string]any{"aud": "other-app", "azp": "other-app"}
			},
			want: []string{"fail ID token audience does not include the client"},
		},
		{
			name: "azp names another client",
			edit: func(o *testutil.OIDCLoginOptions) {
				o.IDTokenClaims = map[string]any{"aud": []string{"web-app", "admin-console"}, "azp": "admin-console"}
			},
			want: []string{"fail ID token was issued to a different client (azp)"},
		},
	})
}

func TestOIDC006TokenTimes(t *testing.T) {
	claims := func(c map[string]any) func(*testutil.OIDCLoginOptions) {
		return func(o *testutil.OIDCLoginOptions) { o.IDTokenClaims = c }
	}
	runOIDCCases(t, tokenTimes{}, []oidcCase{
		{name: "valid", want: []string{"pass Tokens were within their validity window"}},
		{
			name: "expired",
			edit: claims(map[string]any{"iat": tokenAt.Add(-15 * time.Minute).Unix(), "exp": tokenAt.Add(-10 * time.Minute).Unix()}),
			want: []string{"fail ID token had expired when it arrived"},
		},
		{
			name: "expired within skew",
			edit: claims(map[string]any{"iat": tokenAt.Add(-6 * time.Minute).Unix(), "exp": tokenAt.Add(-1 * time.Minute).Unix()}),
			want: []string{"warn ID token had expired when it arrived (within clock-skew tolerance)"},
		},
		{
			name: "not yet valid",
			edit: claims(map[string]any{"iat": tokenAt.Add(10 * time.Minute).Unix(), "nbf": tokenAt.Add(10 * time.Minute).Unix(), "exp": tokenAt.Add(15 * time.Minute).Unix()}),
			want: []string{"fail ID token was not yet valid when it arrived"},
		},
		{
			name: "issued in the future",
			edit: claims(map[string]any{"iat": tokenAt.Add(10 * time.Minute).Unix(), "exp": tokenAt.Add(15 * time.Minute).Unix()}),
			want: []string{"warn Token was issued in the future"},
		},
		{
			name: "no exp",
			edit: claims(map[string]any{"exp": nil}),
			want: []string{"fail ID token has no expiry"},
		},
		{
			name: "zero lifetime",
			edit: claims(map[string]any{"iat": tokenAt.Unix(), "exp": tokenAt.Unix()}),
			want: []string{"warn Token expires before it was issued", "warn ID token had expired when it arrived (within clock-skew tolerance)"},
		},
	})
}

// cors sets the Origin the browser sent with the default fixture's token
// request and, unless allow is empty, the IdP's Access-Control-Allow-Origin.
func cors(origin, allow string) func(*har.HAR) {
	return func(h *har.HAR) {
		e := &h.Log.Entries[len(h.Log.Entries)-1]
		e.Request.Headers = append(e.Request.Headers, har.NameValue{Name: "Origin", Value: origin})
		if allow != "" {
			e.Response.Headers = append(e.Response.Headers, har.NameValue{Name: "Access-Control-Allow-Origin", Value: allow})
		}
	}
}

// TestOIDC007ExplainsReload checks that a code refused because the
// callback page was reloaded is explained as that, not with the generic
// list of invalid_grant causes.
func TestOIDC007ExplainsReload(t *testing.T) {
	got := tokenEndpointError{}.Check(oidcCtx(t, oidcCase{
		edit: func(o *testutil.OIDCLoginOptions) { o.Reloads = 1 },
	}))
	if len(got) != 1 || got[0].Severity != Fail || got[0].OIDCFlow == nil || *got[0].OIDCFlow != 1 {
		t.Fatalf("findings = %s, want one FAIL on the repeat (flow index 1)", describe(got))
	}
	f := got[0]
	if !strings.Contains(f.Detail, "loaded again") || !strings.Contains(f.Detail, "login 1") {
		t.Errorf("detail does not explain the reload: %q", f.Detail)
	}
	if !strings.Contains(f.Fix, "replace the callback URL") {
		t.Errorf("fix does not say how to prevent it: %q", f.Fix)
	}
	if !slices.ContainsFunc(f.Evidence, func(e Evidence) bool { return e.Label == "Repeats" }) {
		t.Errorf("no Repeats evidence: %+v", f.Evidence)
	}
}

func TestOIDC007TokenEndpoint(t *testing.T) {
	runOIDCCases(t, tokenEndpointError{}, []oidcCase{
		{name: "success", want: []string{"pass Token requests succeeded"}},
		{
			name: "callback reloaded",
			edit: func(o *testutil.OIDCLoginOptions) { o.Reloads = 2 },
			want: []string{"fail Token endpoint refused", "fail Token endpoint refused"},
		},
		{
			name: "invalid grant",
			edit: func(o *testutil.OIDCLoginOptions) {
				o.TokenStatus, o.TokenBody = 400, `{"error":"invalid_grant","error_description":"Code not valid"}`
			},
			want: []string{"fail Token endpoint refused the authorization code"},
		},
		{
			name: "origin refused, body hidden",
			edit: func(o *testutil.OIDCLoginOptions) { o.TokenStatus, o.TokenBody = 403, " " },
			har:  cors("https://app.example.org", ""),
			want: []string{"fail Browser blocked the token response (CORS)"},
			reason: "real Brave capture: Keycloak answers 403 without Access-Control-Allow-Origin, " +
				"and the browser records no body",
		},
		{
			name:   "200 the page could not read",
			har:    cors("https://app.example.org", ""),
			want:   []string{"fail Browser blocked the token response (CORS)"},
			reason: "the IdP issued tokens, but without the header the browser withholds them from the page",
		},
		{
			name: "origin allowed",
			har:  cors("https://app.example.org", "https://app.example.org"),
			want: []string{"pass Token requests succeeded"},
		},
		{
			name: "any origin allowed",
			har:  cors("https://app.example.org", "*"),
			want: []string{"pass Token requests succeeded"},
		},
		{
			name:   "same origin needs no header",
			har:    cors("https://idp.example.com", ""),
			want:   []string{"pass Token requests succeeded"},
			reason: "browsers send Origin on every POST, so it alone does not make a call cross-origin",
		},
		{
			name: "never completed",
			edit: func(o *testutil.OIDCLoginOptions) { o.TokenStatus, o.TokenBody = 0, "" },
			har: func(h *har.HAR) {
				h.Log.Entries[len(h.Log.Entries)-1].Response.Status = 0
			},
			want:   []string{"warn Token request never completed"},
			reason: "status 0 is how browsers record a CORS-blocked request",
		},
		{
			name: "gateway answered",
			edit: func(o *testutil.OIDCLoginOptions) { o.TokenStatus, o.TokenBody = 502, "<html>Bad gateway</html>" },
			want: []string{"fail Token endpoint refused the authorization code"},
		},
		{
			name: "refresh refused",
			har: func(h *har.HAR) {
				e := testutil.PostFormEntry("https://idp.example.com/realms/lab/protocol/openid-connect/token",
					url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"r-0123456789"}}, tokenAt.Add(time.Hour), 400)
				e.Response.Content = har.Content{MimeType: "application/json", Text: `{"error":"invalid_grant"}`}
				h.Log.Entries = append(h.Log.Entries, e)
			},
			want: []string{"warn Token endpoint refused a refresh_token request"},
		},
	})

	t.Run("missing code_verifier is named", func(t *testing.T) {
		ctx := oidcCtx(t, oidcCase{edit: func(o *testutil.OIDCLoginOptions) {
			o.OmitCodeVerifier = true
			o.TokenStatus, o.TokenBody = 400, `{"error":"invalid_grant","error_description":"PKCE verification failed"}`
		}})
		got := tokenEndpointError{}.Check(ctx)
		if len(got) != 1 || !strings.Contains(got[0].Fix, "code_verifier") {
			t.Errorf("findings = %+v, want a fix naming the code_verifier", got)
		}
	})
}

func TestOIDC008InsecurePatterns(t *testing.T) {
	unsigned := rawToken(`{"alg":"none"}`, defaultClaims(), "")
	runOIDCCases(t, insecurePatterns{}, []oidcCase{
		{name: "code with PKCE", want: []string{"pass No insecure OAuth patterns found"}},
		{
			name: "browser app without PKCE",
			edit: func(o *testutil.OIDCLoginOptions) { o.PKCE = false },
			want: []string{"warn Browser app uses authorization codes without PKCE"},
		},
		{
			name:   "server app without PKCE",
			edit:   func(o *testutil.OIDCLoginOptions) { o.PKCE = false },
			har:    func(h *har.HAR) { h.Log.Entries = h.Log.Entries[:2] },
			want:   []string{"info Authorization code flow without PKCE"},
			reason: "no browser token call: the code is redeemed by a server, which may hold a secret",
		},
		{
			name: "plain PKCE",
			edit: func(o *testutil.OIDCLoginOptions) { o.ChallengeMethod = "plain" },
			want: []string{"warn PKCE uses the plain method"},
		},
		{
			name: "PKCE method omitted defaults to plain",
			edit: func(o *testutil.OIDCLoginOptions) { o.ChallengeMethod = "-" },
			want: []string{"warn PKCE uses the plain method"},
		},
		{
			name: "implicit flow",
			edit: func(o *testutil.OIDCLoginOptions) { o.ResponseType = "id_token token" },
			want: []string{"warn Implicit flow returns access tokens in the browser"},
		},
		{
			name: "client secret in the browser",
			edit: func(o *testutil.OIDCLoginOptions) { o.ClientSecret = "s3cr3t-value-0123456789" },
			want: []string{"warn Client secret sent from the browser"},
		},
		{
			name: "unsigned ID token",
			edit: func(o *testutil.OIDCLoginOptions) { o.TokenBody = tokenBody(unsigned) },
			want: []string{"warn ID token is unsigned (alg none)"},
		},
	})
}

func TestOIDC009Signature(t *testing.T) {
	other := testutil.NewKeyPair(t, "other.example.com")
	claims := defaultClaims()
	runOIDCCases(t, idTokenSignature{}, []oidcCase{
		{name: "no keys supplied", want: []string{"info ID token signatures not checked"}},
		{name: "verified", keys: true, want: []string{"pass ID token signatures verified"}},
		{
			name: "signed by another key with the same kid",
			edit: func(o *testutil.OIDCLoginOptions) {
				o.TokenBody = tokenBody(testutil.SignJWT(t, other.Key, "lab-key-1", claims))
			},
			keys: true,
			want: []string{"fail ID token signature is invalid"},
		},
		{
			name: "key not in the key set",
			edit: func(o *testutil.OIDCLoginOptions) {
				o.TokenBody = tokenBody(testutil.SignJWT(t, other.Key, "rotated-key-2", claims))
			},
			keys: true,
			want: []string{"info ID token signature could not be checked"},
		},
		{
			name: "shared-secret signature",
			edit: func(o *testutil.OIDCLoginOptions) {
				o.TokenBody = tokenBody(rawToken(`{"alg":"HS256","kid":"lab-key-1"}`, claims, "bWFj"))
			},
			keys: true,
			want: []string{"info ID token signature could not be checked"},
		},
		{
			name: "unsigned",
			edit: func(o *testutil.OIDCLoginOptions) { o.TokenBody = tokenBody(rawToken(`{"alg":"none"}`, claims, "")) },
			keys: true,
			want: []string{"fail ID token is unsigned"},
		},
	})
}

// TestOIDCRulesQuietWithoutOIDC: a SAML-only or empty capture gets no
// OIDC findings at all, not even passes.
func TestOIDCRulesQuietWithoutOIDC(t *testing.T) {
	reg, err := DefaultRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []Context{{}, samlCtx(t, login{})} {
		for _, f := range Run(ctx, reg) {
			if strings.HasPrefix(f.RuleID, "OIDC") {
				t.Errorf("unexpected %s %s %q", f.RuleID, f.Severity, f.Title)
			}
		}
	}
}

// TestOIDC003QuotesTokenEndpoint: when the token request's redirect_uri
// differs and the IdP said so, the IdP's words are in the evidence.
func TestOIDC003QuotesTokenEndpoint(t *testing.T) {
	ctx := oidcCtx(t, oidcCase{edit: func(o *testutil.OIDCLoginOptions) {
		o.TokenRedirectURI = testutil.Ptr("https://app.example.org/callback/")
		o.TokenStatus, o.TokenBody = 400, `{"error":"invalid_grant","error_description":"Incorrect redirect_uri"}`
	}})
	got := redirectURIMismatch{}.Check(ctx)
	if len(got) != 1 || !strings.Contains(got[0].Title, "differs") || !strings.Contains(got[0].Fix, "trailing slash") {
		t.Fatalf("findings = %s", describe(got))
	}
	if ev := got[0].Evidence[len(got[0].Evidence)-1]; ev.Label != "IdP said" || ev.Value != "Incorrect redirect_uri" {
		t.Errorf("last evidence = %+v, want the IdP's message", ev)
	}
}
