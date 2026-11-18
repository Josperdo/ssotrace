package oidc

import (
	"strings"
	"testing"
)

func TestParseTokenResponse(t *testing.T) {
	idTok := token(rs256, `{"iss":"https://idp.example.com","aud":"web-app"}`)
	accessJWT := token(rs256, `{"iss":"https://idp.example.com","aud":"api"}`)
	tests := []struct {
		name    string
		body    string
		check   func(t *testing.T, r *TokenResponse)
		wantErr string
	}{
		{
			name: "success with JWT access token",
			body: `{"access_token":"` + accessJWT + `","id_token":"` + idTok + `","token_type":"Bearer","expires_in":300}`,
			check: func(t *testing.T, r *TokenResponse) {
				if r.IDToken == nil || r.AccessToken == nil || r.AccessToken.Claims.Audience[0] != "api" || !r.HasAccessToken {
					t.Errorf("response = %+v", r)
				}
			},
		},
		{
			name: "opaque access token is not parsed",
			body: `{"access_token":"opaque.with.dots-` + planted + `","token_type":"Bearer"}`,
			check: func(t *testing.T, r *TokenResponse) {
				if r.AccessToken != nil || !r.HasAccessToken {
					t.Errorf("response = %+v", r)
				}
			},
		},
		{
			name: "unreadable id token is reported, not fatal",
			body: `{"id_token":"` + planted + `"}`,
			check: func(t *testing.T, r *TokenResponse) {
				if r.IDToken != nil || !strings.Contains(r.IDTokenError, "segments") || strings.Contains(r.IDTokenError, planted) {
					t.Errorf("id token error = %q", r.IDTokenError)
				}
			},
		},
		{
			name: "error response",
			body: `{"error":"invalid_grant","error_description":"Code not valid"}`,
			check: func(t *testing.T, r *TokenResponse) {
				if r.Error != "invalid_grant" || r.HasAccessToken {
					t.Errorf("response = %+v", r)
				}
			},
		},
		{name: "html", body: "<html>" + planted, wantErr: "not a JSON object"},
		{name: "too large", body: `{"x":"` + strings.Repeat("a", MaxTokenResponse) + `"}`, wantErr: "over the"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ParseTokenResponse([]byte(tt.body))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) || strings.Contains(err.Error(), planted) {
					t.Fatalf("error = %v, want containing %q and no token content", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTokenResponse: %v", err)
			}
			tt.check(t, r)
		})
	}
}

func TestFragmentParams(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://app.example.org/cb#state=s&code=c", true},
		{"https://app.example.org/cb#access_token=a&token_type=Bearer", true},
		{"https://app.example.org/cb#error=access_denied", true},
		{"https://app.example.org/cb#section-2", false},
		{"https://app.example.org/cb?code=c", false}, // query, not fragment
	}
	for _, tt := range tests {
		_, err := FragmentParams(tt.url)
		if got := err == nil; got != tt.want {
			t.Errorf("FragmentParams(%q) ok = %v, want %v", tt.url, got, tt.want)
		}
	}
}

func TestOpenID(t *testing.T) {
	for scope, want := range map[string]bool{"openid profile": true, "profile email": false, "openidx": false, "": false} {
		if got := (&AuthorizationRequest{Scope: scope}).OpenID(); got != want {
			t.Errorf("OpenID(%q) = %v, want %v", scope, got, want)
		}
	}
}
