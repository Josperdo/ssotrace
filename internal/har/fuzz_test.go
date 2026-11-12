package har

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzDecode feeds arbitrary bytes to the loader. Every HAR is hostile
// input, so the only acceptable outcomes are a HAR or an error: never a
// panic, a hang, or an error message that repeats the input.
func FuzzDecode(f *testing.F) {
	for _, name := range []string{"chrome.har", "firefox.har", "safari.har"} {
		if b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "har", name)); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(`{"log":{"entries":[]}}`))
	f.Add([]byte("\xEF\xBB\xBF{\"log\":{\"entries\":[{}]}}"))
	f.Add([]byte(`{"log":{"entries":[{"request":{"bodySize":"x"}}]}}`))

	const marker = "FUZZSECRETMARKER"
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := Decode(bytes.NewReader(data), 1<<20)
		if err != nil {
			if strings.Contains(err.Error(), marker) && bytes.Contains(data, []byte(marker)) {
				t.Fatalf("error echoes file content: %v", err)
			}
			return
		}
		// Every accessor on a decoded entry must also be safe.
		for i := range h.Log.Entries {
			e := &h.Log.Entries[i]
			_, _ = e.Started()
			_, _ = e.Response.Content.Bytes()
			_, _ = e.Request.QueryParam("SAMLRequest")
			_, _ = e.Request.FormParam("SAMLResponse")
			_, _ = e.Request.Header("Content-Type")
		}
	})
}
