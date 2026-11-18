package flow

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/Josperdo/ssotrace/internal/testutil"
)

func TestTraceOIDCDelivery(t *testing.T) {
	for _, delivery := range []string{"query", "form_post", "fragment"} {
		t.Run(delivery, func(t *testing.T) {
			o := testutil.DefaultOIDCLoginOptions()
			o.Delivery = delivery
			login := testutil.NewOIDCLogin(t, o)

			tr := TraceOIDC(login.HAR)
			if len(tr.Flows) != 1 {
				t.Fatalf("flows = %d, want 1", len(tr.Flows))
			}
			f := tr.Flows[0]
			if f.Authorization == nil || f.Callback == nil || f.Token == nil {
				t.Fatalf("flow incomplete: auth=%v callback=%v token=%v", f.Authorization != nil, f.Callback != nil, f.Token != nil)
			}
			if f.StateMismatch {
				t.Error("StateMismatch on matching state")
			}
			if got := string(f.Callback.Delivery); got != delivery {
				t.Errorf("delivery = %q, want %q", got, delivery)
			}
			if f.Callback.URL != o.RedirectURI {
				t.Errorf("callback URL = %q, want %q", f.Callback.URL, o.RedirectURI)
			}
			a := f.Authorization.Params
			if a.ClientID != "web-app" || !a.HasCodeChallenge || !a.HasNonce || !a.OpenID() {
				t.Errorf("authorization params = %+v", a)
			}
			r := f.Token.Response
			if r == nil || r.IDToken == nil {
				t.Fatalf("token response = %+v, error %q", r, f.Token.ResponseError)
			}
			if r.IDToken.Claims.Nonce != o.Nonce || !r.HasRefreshToken {
				t.Errorf("token response = %+v", r)
			}
		})
	}
}

func TestTraceOIDCPairing(t *testing.T) {
	tests := []struct {
		name  string
		edit  func(*testutil.OIDCLoginOptions)
		check func(t *testing.T, tr *OIDCTrace)
	}{
		{
			name: "state mismatch pairs by redirect_uri",
			edit: func(o *testutil.OIDCLoginOptions) { o.CallbackState = testutil.Ptr("st-somebody-else-entirely") },
			check: func(t *testing.T, tr *OIDCTrace) {
				if len(tr.Flows) != 1 || !tr.Flows[0].StateMismatch || tr.Flows[0].Callback == nil {
					t.Errorf("flows = %+v, want one flow with StateMismatch", tr.Flows)
				}
			},
		},
		{
			name: "state dropped by callback is a mismatch",
			edit: func(o *testutil.OIDCLoginOptions) { o.CallbackState = testutil.Ptr("") },
			check: func(t *testing.T, tr *OIDCTrace) {
				if len(tr.Flows) != 1 || !tr.Flows[0].StateMismatch {
					t.Errorf("flows = %+v, want one flow with StateMismatch", tr.Flows)
				}
			},
		},
		{
			name: "no state on either side still pairs",
			edit: func(o *testutil.OIDCLoginOptions) { o.State = "" },
			check: func(t *testing.T, tr *OIDCTrace) {
				if len(tr.Flows) != 1 || tr.Flows[0].Callback == nil || tr.Flows[0].StateMismatch {
					t.Errorf("flows = %+v, want one paired flow without mismatch", tr.Flows)
				}
			},
		},
		{
			name: "error callback",
			edit: func(o *testutil.OIDCLoginOptions) {
				o.Error, o.ErrorDescription = "access_denied", "User canceled"
			},
			check: func(t *testing.T, tr *OIDCTrace) {
				f := tr.Flows[0]
				if f.Callback == nil || f.Callback.Params.Error != "access_denied" || f.Token != nil {
					t.Errorf("flow = %+v", f)
				}
			},
		},
		{
			name: "token error response",
			edit: func(o *testutil.OIDCLoginOptions) {
				o.TokenStatus = 400
				o.TokenBody = `{"error":"invalid_grant","error_description":"Code not valid"}`
			},
			check: func(t *testing.T, tr *OIDCTrace) {
				tok := tr.Flows[0].Token
				if tok == nil || tok.HTTPStatus != 400 || tok.Response == nil || tok.Response.Error != "invalid_grant" {
					t.Errorf("token = %+v", tok)
				}
			},
		},
		{
			name: "token body not JSON",
			edit: func(o *testutil.OIDCLoginOptions) { o.TokenStatus, o.TokenBody = 502, "<html>Bad gateway</html>" },
			check: func(t *testing.T, tr *OIDCTrace) {
				tok := tr.Flows[0].Token
				if tok == nil || tok.Response != nil || !strings.Contains(tok.ResponseError, "not a JSON object") {
					t.Errorf("token = %+v", tok)
				}
			},
		},
		{
			name: "token redeems a code the capture never saw",
			edit: func(o *testutil.OIDCLoginOptions) { o.TokenCode = testutil.Ptr("code-from-somewhere-else-99") },
			check: func(t *testing.T, tr *OIDCTrace) {
				if len(tr.Flows) != 2 || tr.Flows[0].Token != nil || tr.Flows[1].Token == nil || tr.Flows[1].Authorization != nil {
					t.Errorf("flows = %+v, want login without token plus a token-only flow", tr.Flows)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := testutil.DefaultOIDCLoginOptions()
			tt.edit(&o)
			tt.check(t, TraceOIDC(testutil.NewOIDCLogin(t, o).HAR))
		})
	}
}

// TestTraceOIDCRepeatedCallback covers a reload (or Back) on the callback
// page: the same callback arrives again after its request was answered.
func TestTraceOIDCRepeatedCallback(t *testing.T) {
	for _, delivery := range []string{"query", "form_post"} {
		t.Run(delivery, func(t *testing.T) {
			o := testutil.DefaultOIDCLoginOptions()
			o.Delivery, o.Reloads = delivery, 2
			tr := TraceOIDC(testutil.NewOIDCLogin(t, o).HAR)

			if len(tr.Flows) != 3 {
				t.Fatalf("flows = %d, want the login plus two repeats", len(tr.Flows))
			}
			if first := tr.Flows[0]; first.Repeats != nil || first.Token == nil || first.Token.HTTPStatus != 200 {
				t.Errorf("first flow = %+v, want the original login with its successful token call", first)
			}
			for i, f := range tr.Flows[1:] {
				if f.Repeats == nil || *f.Repeats != 0 {
					t.Errorf("flow %d Repeats = %v, want 0", i+1, f.Repeats)
				}
				if f.Authorization != nil || f.Callback == nil || f.Token == nil || f.Token.HTTPStatus != 400 {
					t.Errorf("flow %d = %+v, want callback plus refused token call", i+1, f)
				}
			}
		})
	}

	t.Run("same state with a different code is not a repeat", func(t *testing.T) {
		o := testutil.DefaultOIDCLoginOptions()
		o.Reloads = 1
		h := testutil.NewOIDCLogin(t, o).HAR
		cb := &h.Log.Entries[3].Request // the reloaded callback
		cb.URL = strings.Replace(cb.URL, url.QueryEscape(o.Code), "a-different-code-0001", 1)

		tr := TraceOIDC(h)
		if len(tr.Flows) < 2 || tr.Flows[1].Repeats != nil || tr.Flows[1].Callback == nil {
			t.Errorf("flows = %+v, want the second callback treated as unrelated", tr.Flows)
		}
	})
}

func TestTraceOIDCUnsolicited(t *testing.T) {
	// A callback and a refresh with no login before them: recording started
	// late. The callback is its own flow; the refresh is not a login.
	cb := testutil.GetEntry(t, "https://app.example.org/callback?state=st-unknown-123&code=code-xyz-0123456789", testutil.RefTime, 200)
	refresh := testutil.PostFormEntry("https://idp.example.com/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"r-0123456789"}}, testutil.RefTime, 200)
	tr := TraceOIDC(testutil.NewHAR(cb, refresh))
	if len(tr.Flows) != 1 || tr.Flows[0].Authorization != nil || tr.Flows[0].Callback == nil {
		t.Errorf("flows = %+v, want one callback-only flow", tr.Flows)
	}
	if len(tr.Other) != 1 || tr.Other[0].Request.GrantType != "refresh_token" {
		t.Errorf("other = %+v, want the refresh call", tr.Other)
	}
}

// TestTraceOIDCKeepsSecretsOut checks that the JSON model, which reaches
// --format json output, never carries a code, state, nonce, or token.
func TestTraceOIDCKeepsSecretsOut(t *testing.T) {
	for _, delivery := range []string{"query", "form_post", "fragment"} {
		o := testutil.DefaultOIDCLoginOptions()
		o.Delivery = delivery
		login := testutil.NewOIDCLogin(t, o)
		b, err := json.Marshal(TraceOIDC(login.HAR))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []string{o.Code, o.State, o.Nonce, login.IDToken, "opaque-access-token-0123456789", "opaque-refresh-token"} {
			if strings.Contains(string(b), s) {
				t.Errorf("%s: JSON model contains %q", delivery, s)
			}
		}
	}
}

func TestTraceOIDCIgnoresUnrelatedFragments(t *testing.T) {
	e := testutil.GetEntry(t, "https://app.example.org/page", testutil.RefTime, 302)
	e.Response.RedirectURL = "https://app.example.org/other#error=1"
	if tr := TraceOIDC(testutil.NewHAR(e)); len(tr.Flows) != 0 {
		t.Errorf("flows = %+v, want none", tr.Flows)
	}
}
