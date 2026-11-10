package flow

import (
	"testing"

	"github.com/Josperdo/ssotrace/internal/har"
)

func TestDetect(t *testing.T) {
	const form = "application/x-www-form-urlencoded"
	get := func(url string) har.Entry {
		return har.Entry{Request: har.Request{Method: "GET", URL: url}}
	}
	post := func(url, body string) har.Entry {
		return har.Entry{Request: har.Request{
			Method:   "POST",
			URL:      url,
			PostData: &har.PostData{MimeType: form, Text: body},
		}}
	}

	tests := []struct {
		name  string
		entry har.Entry
		want  Protocol
	}{
		// SAML
		{"saml redirect binding", get("https://idp.example.org/sso?SAMLRequest=abc&RelayState=x"), SAML},
		{"saml post binding", post("https://app.example.com/acs", "SAMLResponse=abc"), SAML},
		{"saml artifact", get("https://app.example.com/acs?SAMLart=abc"), SAML},
		{"saml logout response", get("https://app.example.com/slo?SAMLResponse=abc"), SAML},

		// OIDC / OAuth
		{"authorization request", get("https://idp.example.org/authorize?client_id=c&response_type=code&state=s"), OIDC},
		{"query callback", get("https://app.example.com/cb?code=abc&state=s"), OIDC},
		{"error callback", get("https://app.example.com/cb?error=access_denied&state=s"), OIDC},
		{"form_post callback", post("https://app.example.com/cb", "id_token=abc&state=s"), OIDC},
		{"token request", post("https://idp.example.org/token", "grant_type=authorization_code&code=abc"), OIDC},

		// Not SSO
		{"plain page", get("https://app.example.com/home"), None},
		{"code without state", get("https://app.example.com/verify?code=123456"), None},
		{"client_id alone", get("https://api.example.com/x?client_id=c"), None},
		{"lowercase saml name", get("https://app.example.com/?samlrequest=abc"), None},
		{"saml name in a JSON body", har.Entry{Request: har.Request{
			Method:   "POST",
			URL:      "https://app.example.com/api",
			PostData: &har.PostData{MimeType: "application/json", Text: `{"SAMLResponse":"abc"}`},
		}}, None},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Detect(&tt.entry); got != tt.want {
				t.Errorf("Detect = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProtocolString(t *testing.T) {
	for p, want := range map[Protocol]string{None: "none", SAML: "saml", OIDC: "oidc", Protocol(9): "unknown"} {
		if got := p.String(); got != want {
			t.Errorf("Protocol(%d).String() = %q, want %q", int(p), got, want)
		}
	}
}
