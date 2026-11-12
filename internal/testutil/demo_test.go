package testutil

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/Josperdo/ssotrace/internal/har"
)

var writeDemo = flag.Bool("write-demo", false, "rewrite testdata/demo/broken-login.har")

// demoHAR is the capture behind the README's terminal recording: an
// SP-initiated login that fails because the IdP addressed the assertion to
// the wrong application, signed with SHA-1, around a real-looking session
// cookie so `ssotrace scan` has something to find. Every value is
// synthetic (example.com/org, a key generated on the spot).
func demoHAR(t testing.TB) *har.HAR {
	req := DefaultAuthnRequestOptions()
	resp := DefaultResponseOptions()
	resp.Audience = "https://old-app.example.org/saml/metadata"
	resp.SHA1 = true
	login := NewSAMLLogin(t, req, resp)

	post := &login.HAR.Log.Entries[1]
	post.Request.Cookies = []har.Cookie{{Name: "app_session", Value: "s3ss10n-0123456789abcdef0123456789abcdef", Path: "/", Secure: true, HTTPOnly: true}}
	post.Request.Headers = append(post.Request.Headers, har.NameValue{Name: "Cookie", Value: "app_session=s3ss10n-0123456789abcdef0123456789abcdef"})
	return login.HAR
}

// TestDemoHAR keeps the committed demo capture readable. Regenerate it with:
//
//	go test ./internal/testutil -run TestDemoHAR -write-demo
func TestDemoHAR(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "demo", "broken-login.har")
	if *writeDemo {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, MarshalHAR(t, demoHAR(t)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("demo HAR not generated yet: %v", err)
	}
	if _, err := har.Decode(bytes.NewReader(b), har.DefaultMaxBytes); err != nil {
		t.Errorf("demo HAR does not load: %v", err)
	}
}
