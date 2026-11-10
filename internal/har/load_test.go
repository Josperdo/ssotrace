package har

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoadBrowserFixtures checks that each browser's export shape decodes to
// the same facts: the same requests, the same instant, the same decoded SSO
// parameters, despite different header case, timestamp offsets, and
// optional fields.
func TestLoadBrowserFixtures(t *testing.T) {
	wantStart := time.Date(2026, 1, 15, 10, 0, 0, 123_000_000, time.UTC)

	tests := []struct {
		file        string
		wantCreator string
		wantBrowser bool   // Firefox writes the optional "browser" object
		wantBody    string // decoded body of the first response
	}{
		{"chrome.har", "WebInspector", false, "<html></html>"},         // base64-encoded content
		{"firefox.har", "Firefox", true, ""},                           // body not saved
		{"safari.har", "WebKit Web Inspector", false, "<html></html>"}, // plain text content
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			h, err := Load(filepath.Join("..", "..", "testdata", "har", tt.file), DefaultMaxBytes)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			log := h.Log
			if log.Creator.Name != tt.wantCreator {
				t.Errorf("creator = %q, want %q", log.Creator.Name, tt.wantCreator)
			}
			if (log.Browser != nil) != tt.wantBrowser {
				t.Errorf("browser present = %v, want %v", log.Browser != nil, tt.wantBrowser)
			}
			if len(log.Entries) != 2 {
				t.Fatalf("entries = %d, want 2", len(log.Entries))
			}

			get, post := &log.Entries[0], &log.Entries[1]

			started, err := get.Started()
			if err != nil {
				t.Fatalf("Started: %v", err)
			}
			if !started.Equal(wantStart) {
				t.Errorf("Started = %v, want %v", started, wantStart)
			}

			if v, _ := get.Request.QueryParam("SAMLRequest"); v != "ZmFrZS1zYW1sLXJlcXVlc3Q=" {
				t.Errorf("SAMLRequest query param = %q", v)
			}
			if v, _ := post.Request.FormParam("SAMLResponse"); v != "c2FtbC+yZXNwb25zZQ==" {
				t.Errorf("SAMLResponse form param = %q", v)
			}
			if v, ok := post.Request.Header("Content-Type"); !ok || v != "application/x-www-form-urlencoded" {
				t.Errorf("Content-Type header = %q, %v", v, ok)
			}
			if v, _ := post.Response.Header("location"); v != "https://app.example.com/home" {
				t.Errorf("Location header = %q", v)
			}

			body, err := get.Response.Content.Bytes()
			if err != nil {
				t.Fatalf("Content.Bytes: %v", err)
			}
			if string(body) != tt.wantBody {
				t.Errorf("body = %q, want %q", body, tt.wantBody)
			}
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	const secret = "SUPERSECRETVALUE"

	tests := []struct {
		name      string
		input     string
		wantIs    error  // optional sentinel
		wantInMsg string // substring of the error message
	}{
		{"empty", "", ErrNotHAR, "empty"},
		{"top-level array", `[]`, ErrNotHAR, `expected '{'`},
		{"missing log", `{"other":1}`, ErrNotHAR, `missing "log"`},
		{"log is a string", `{"log":"` + secret + `"}`, nil, "found a string"},
		{"entries not an array", `{"log":{"entries":{}}}`, nil, "entries: expected '['"},
		{"truncated", `{"log":{"entries":[{"request":`, ErrNotHAR, "truncated"},
		{"syntax error", `{"log":{"entries":[}}`, ErrNotHAR, "malformed JSON at byte"},
		{"wrong field type", `{"log":{"entries":[{"request":{"bodySize":"` + secret + `"}}]}}`, nil, `entry 0: field "request.bodySize" has the wrong type`},
		{"duplicate log", `{"log":{"entries":[]},"log":{"entries":[]}}`, ErrNotHAR, `duplicate "log"`},
		{"duplicate entries", `{"log":{"entries":[],"entries":[]}}`, nil, `duplicate "entries"`},
		{"trailing data", `{"log":{"entries":[]}} {}`, ErrNotHAR, "unexpected data after"},
		{"gzip", "\x1f\x8b\x08\x00", ErrNotHAR, "gzip-compressed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(tt.input), DefaultMaxBytes)
			if err == nil {
				t.Fatal("Decode succeeded, want error")
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("error %q is not %v", err, tt.wantIs)
			}
			if !strings.Contains(err.Error(), tt.wantInMsg) {
				t.Errorf("error %q does not contain %q", err, tt.wantInMsg)
			}
			// Security rule: error messages never echo file content.
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error %q leaks file content", err)
			}
			if strings.Count(err.Error(), ErrNotHAR.Error()) > 1 {
				t.Errorf("error %q repeats %q", err, ErrNotHAR)
			}
		})
	}
}

func TestDecodeAccepts(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantEntries int
	}{
		{"minimal", `{"log":{"entries":[]}}`, 0},
		{"no entries key", `{"log":{"version":"1.2"}}`, 0},
		{"utf-8 BOM", "\xEF\xBB\xBF" + `{"log":{"entries":[{}]}}`, 1},
		{"unknown fields ignored", `{"_x":1,"log":{"_y":[1,2],"pages":[{}],"entries":[{"_z":{}}]}}`, 1},
		{"trailing whitespace", "{\"log\":{\"entries\":[]}}\n\n", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := Decode(strings.NewReader(tt.input), DefaultMaxBytes)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got := len(h.Log.Entries); got != tt.wantEntries {
				t.Errorf("entries = %d, want %d", got, tt.wantEntries)
			}
		})
	}
}

func TestDecodeSizeLimit(t *testing.T) {
	doc := `{"log":{"entries":[]}}`
	n := int64(len(doc))

	if _, err := Decode(strings.NewReader(doc), n); err != nil {
		t.Errorf("exactly at limit: %v", err)
	}
	_, err := Decode(strings.NewReader(doc), n-1)
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("one byte over limit: got %v, want ErrTooLarge", err)
	}
	// Valid JSON followed by padding still trips the limit: the reader
	// counts every byte, not just the ones the decoder needed.
	padded := doc + strings.Repeat(" ", 100)
	if _, err := Decode(strings.NewReader(padded), n+10); !errors.Is(err, ErrTooLarge) {
		t.Errorf("padded over limit: got %v, want ErrTooLarge", err)
	}
}

// TestLoadRejectsLargeFile uses a sparse file: it reports a 300 MiB size but
// occupies almost no disk, and Load must reject it from the size alone.
func TestLoadRejectsLargeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.har")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(300 << 20); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = Load(path, DefaultMaxBytes)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	if want := "300.0 MiB, limit 256.0 MiB"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not contain %q", err, want)
	}
}

func TestLoadFileErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.har"), DefaultMaxBytes); err == nil {
		t.Error("missing file: want error")
	}
	if _, err := Load(dir, DefaultMaxBytes); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("directory: got %v", err)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0 bytes"},
		{1023, "1023 bytes"},
		{1024, "1.0 KiB"},
		{256 << 20, "256.0 MiB"},
		{3 << 30, "3.0 GiB"},
	}
	for _, tt := range tests {
		if got := FormatBytes(tt.n); got != tt.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// Benchmark-free sanity check that Decode does not need the whole input in
// one buffer: a reader that yields one byte at a time still works.
func TestDecodeOneByteReader(t *testing.T) {
	doc := []byte(`{"log":{"entries":[{"request":{"method":"GET"}}]}}`)
	h, err := Decode(&oneByteReader{r: bytes.NewReader(doc)}, DefaultMaxBytes)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got := h.Log.Entries[0].Request.Method; got != "GET" {
		t.Errorf("method = %q", got)
	}
}

type oneByteReader struct{ r *bytes.Reader }

func (o *oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}
