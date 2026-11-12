package redact

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Josperdo/ssotrace/internal/har"
	"github.com/Josperdo/ssotrace/internal/testutil"
)

// Synthetic secret-shaped values. None is real; each is distinctive so a
// test can check it never appears in scanner output.
const (
	fakeJWT      = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.c2lnbmF0dXJlLWZha2U"
	fakeCookie   = "sess-0123456789abcdef0123456789abcdef"
	fakePassword = "correct-horse-battery"
	fakeCode     = "auth-code-0123456789abcdef"
	fakeBearer   = "Bearer opaque-token-0123456789abcdef"
)

func get(t *testing.T, rawURL string) har.Entry {
	t.Helper()
	return testutil.GetEntry(t, rawURL, testutil.RefTime, 200)
}

func kinds(leaks []Leak) map[Kind]int {
	m := map[Kind]int{}
	for _, l := range leaks {
		m[l.Kind]++
	}
	return m
}

func TestScanFindsEachKind(t *testing.T) {
	cookieEntry := get(t, "https://app.example.com/home")
	cookieEntry.Request.Cookies = []har.Cookie{{Name: "session", Value: fakeCookie}}
	cookieEntry.Response.Headers = []har.NameValue{{Name: "Set-Cookie", Value: "session=" + fakeCookie + "; Path=/; SameSite=Lax"}}

	authEntry := get(t, "https://api.example.com/me")
	authEntry.Request.Headers = []har.NameValue{{Name: "Authorization", Value: fakeBearer}}

	loginForm := testutil.PostFormEntry("https://idp.example.org/login",
		url.Values{"username": {"alice"}, "password": {fakePassword}}, testutil.RefTime, 302)

	tokenBody := get(t, "https://idp.example.org/token")
	tokenBody.Response.Content = har.Content{MimeType: "application/json", Text: `{"access_token":"` + fakeJWT + `","token_type":"Bearer"}`}

	tests := []struct {
		name  string
		entry har.Entry
		want  Kind
	}{
		{"cookie array and Set-Cookie", cookieEntry, KindCookie},
		{"authorization header", authEntry, KindCredHeader},
		{"jwt in a URL fragment", get(t, "https://app.example.com/cb#id_token="+fakeJWT+"&state=s"), KindToken},
		{"auth code in query", get(t, "https://app.example.com/cb?code="+fakeCode+"&state=s"), KindToken},
		{"password in a login form", loginForm, KindPassword},
		{"token in a JSON body", tokenBody, KindToken},
		{"email in a URL", get(t, "https://app.example.com/profile?user=alice%40example.com"), KindEmail},
		{"jwt in a page", func() har.Entry {
			e := get(t, "https://app.example.com/")
			e.Response.Content = har.Content{MimeType: "text/html", Text: "<script>var t='" + fakeJWT + "'</script>"}
			return e
		}(), KindJWT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaks := Scan(testutil.NewHAR(tt.entry))
			if kinds(leaks)[tt.want] == 0 {
				t.Fatalf("no %q leak found; got %+v", tt.want, leaks)
			}
			for _, l := range leaks {
				for _, s := range []string{fakeJWT, fakeCookie, fakePassword, fakeCode, fakeBearer} {
					if strings.Contains(l.Preview, s) || strings.Contains(l.Where, s) {
						t.Errorf("leak report contains the secret itself: %+v", l)
					}
				}
			}
		})
	}
}

func TestScanSAML(t *testing.T) {
	login := testutil.NewSAMLLogin(t, testutil.DefaultAuthnRequestOptions(), testutil.DefaultResponseOptions())
	leaks := Scan(login.HAR)

	var where []string
	for _, l := range leaks {
		if l.Kind == KindSAML {
			where = append(where, l.Where)
		}
	}
	joined := strings.Join(where, "\n")
	for _, want := range []string{"SignatureValue", "DigestValue", "NameID", "SessionIndex"} {
		if !strings.Contains(joined, want) {
			t.Errorf("SAML %s not reported; got:\n%s", want, joined)
		}
	}
	for _, l := range leaks {
		if strings.HasSuffix(l.Where, "NameID") && strings.Contains(l.Preview, "alice") {
			t.Errorf("NameID preview reveals the user: %q", l.Preview)
		}
	}
}

// TestScanAcceptsRedactedForms: the markers the redactor writes are not
// leaks. If this fails, every redaction would abort.
func TestScanAcceptsRedactedForms(t *testing.T) {
	e := get(t, "https://app.example.com/cb?code="+url.QueryEscape(Redacted)+"&state="+url.QueryEscape(Redacted))
	e.Request.Cookies = []har.Cookie{{Name: "session", Value: Redacted}}
	e.Request.Headers = []har.NameValue{
		{Name: "Authorization", Value: Redacted},
		{Name: "Cookie", Value: "a=" + Redacted + "; b=" + Redacted},
	}
	e.Response.Headers = []har.NameValue{{Name: "Set-Cookie", Value: "session=" + Redacted + "; Path=/; SameSite=None; Secure"}}
	e.Response.Content = har.Content{MimeType: "text/html", Text: "user " + maskPrefix + "0123456789ab@" + maskDomain +
		" token eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwcyJ9." + jwtSigMarker}

	if leaks := Scan(testutil.NewHAR(e)); len(leaks) != 0 {
		t.Errorf("redacted forms reported as leaks: %+v", leaks)
	}
}

// TestScanUnreadableSAML: a SAML parameter that cannot be decoded cannot be
// shown to be safe, so it is reported rather than skipped.
func TestScanUnreadableSAML(t *testing.T) {
	form := url.Values{"SAMLResponse": {"%%%not-base64%%%"}}
	e := testutil.PostFormEntry("https://app.example.org/acs", form, testutil.RefTime, 200)
	if kinds(Scan(testutil.NewHAR(e)))[KindUnreadable] == 0 {
		t.Error("undecodable SAMLResponse not reported")
	}
}

// TestScanCommentSplitNameID: a NameID split by an XML comment must be read
// in full, the same way canonicalization reads it.
func TestScanCommentSplitNameID(t *testing.T) {
	idp := testutil.NewKeyPair(t, "idp.example.com")
	xml := testutil.Response(t, idp, testutil.DefaultResponseOptions())
	xml = bytes.Replace(xml, []byte(">alice@example.com<"), []byte("><!---->alice@example.com<"), 1)
	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(xml)}}
	e := testutil.PostFormEntry("https://app.example.org/acs", form, testutil.RefTime.Add(time.Second), 302)

	found := false
	for _, l := range Scan(testutil.NewHAR(e)) {
		if strings.HasSuffix(l.Where, "NameID") {
			found = true
		}
	}
	if !found {
		t.Error("NameID hidden behind a comment was not reported")
	}
}

func TestScanLogComment(t *testing.T) {
	h := testutil.NewHAR()
	h.Log.Comment = "exported by alice@example.com"
	leaks := Scan(h)
	if len(leaks) != 1 || leaks[0].Kind != KindEmail || leaks[0].Entry != -1 {
		t.Errorf("leaks = %+v, want one email in the log comment", leaks)
	}
}
