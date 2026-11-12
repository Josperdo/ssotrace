package redact

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Josperdo/ssotrace/internal/har"
	"github.com/Josperdo/ssotrace/internal/testutil"
)

// FuzzRedactLeavesNoSecrets checks redaction's core promise on inputs no
// person would write: for any HAR at all, the redacted copy scans clean.
// A failure here is either a redactor gap or a scanner false positive, and
// both matter, because either one makes `ssotrace redact` refuse to write.
func FuzzRedactLeavesNoSecrets(f *testing.F) {
	login := testutil.NewSAMLLogin(f, testutil.DefaultAuthnRequestOptions(), testutil.DefaultResponseOptions())
	f.Add(testutil.MarshalHAR(f, login.HAR))
	f.Add([]byte(`{"log":{"entries":[{"request":{"method":"GET","url":"https://a.example/cb?code=abc&state=s#id_token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.c2ln","headers":[{"name":"Cookie","value":"a=b"},{"name":"Authorization","value":"Bearer t"}],"cookies":[{"name":"a","value":"b"}]},"response":{"status":200,"headers":[{"name":"Set-Cookie","value":"a=b; Path=/"}],"content":{"mimeType":"text/html","text":"hi alice@example.com"}}}]}}`))
	f.Add([]byte(`{"log":{"entries":[{"request":{"method":"POST","url":"https://a.example/login","postData":{"mimeType":"application/x-www-form-urlencoded","text":"user=a&password=p"}},"response":{"status":302}}]}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := har.Decode(bytes.NewReader(data), 1<<20)
		if err != nil {
			return
		}
		out, err := Redact(h, Options{Salt: testSalt})
		if err != nil {
			t.Fatalf("Redact: %v", err)
		}
		// Check what would be written: the JSON, read back.
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		back, err := har.Decode(bytes.NewReader(b), int64(len(b))+1)
		if err != nil {
			t.Fatalf("redacted output does not read back: %v", err)
		}
		if leaks := Scan(back); len(leaks) > 0 {
			t.Fatalf("redacted output still has %d leak(s), first: %+v", len(leaks), leaks[0])
		}
	})
}
