package saml

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const plantedSecret = "SUPERSECRETVALUE"

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func compress(t *testing.T, kind string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w interface {
		Write([]byte) (int, error)
		Close() error
	}
	switch kind {
	case "deflate":
		fw, err := flate.NewWriter(&buf, flate.BestCompression)
		if err != nil {
			t.Fatal(err)
		}
		w = fw
	case "zlib":
		w = zlib.NewWriter(&buf)
	case "gzip":
		w = gzip.NewWriter(&buf)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodePOST(t *testing.T) {
	msg := []byte("<samlp:Response/>")
	enc := b64(msg)

	tests := []struct {
		name  string
		input string
	}{
		{"plain", enc},
		{"line-wrapped", enc[:8] + "\r\n" + enc[8:]},
		{"padding dropped", strings.TrimRight(enc, "=")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodePOST(tt.input)
			if err != nil {
				t.Fatalf("DecodePOST: %v", err)
			}
			if !bytes.Equal(got, msg) {
				t.Errorf("got %q", got)
			}
		})
	}

	for _, bad := range []string{"", "   ", "!!" + plantedSecret} {
		_, err := DecodePOST(bad)
		if err == nil {
			t.Errorf("DecodePOST(%q) succeeded", bad)
			continue
		}
		if strings.Contains(err.Error(), plantedSecret) {
			t.Errorf("error %q leaks input", err)
		}
	}
}

func TestDecodeRedirect(t *testing.T) {
	msg := []byte(`<samlp:AuthnRequest ID="` + plantedSecret + `"/>`)

	got, err := DecodeRedirect(b64(compress(t, "deflate", msg)))
	if err != nil {
		t.Fatalf("DecodeRedirect: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("got %q", got)
	}

	// The wrong encodings each get a specific explanation.
	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{"zlib", compress(t, "zlib", msg), "zlib header"},
		{"gzip", compress(t, "gzip", msg), "gzip"},
		{"uncompressed", msg, "uncompressed XML"},
		{"garbage", []byte{0xff, 0xff, 0xff}, "not valid DEFLATE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeRedirect(b64(tt.payload))
			if err == nil {
				t.Fatal("DecodeRedirect succeeded")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
			if strings.Contains(err.Error(), plantedSecret) {
				t.Errorf("error %q leaks input", err)
			}
		})
	}
}

// TestDecodeRedirectBomb: 11 MiB of zeros compresses to about 11 KiB. The
// cap must stop it on the inflated size.
func TestDecodeRedirectBomb(t *testing.T) {
	bomb := compress(t, "deflate", make([]byte, MaxInflated+(1<<20)))
	if len(bomb) > 64<<10 {
		t.Fatalf("test setup: bomb is %d bytes, expected a small payload", len(bomb))
	}
	_, err := DecodeRedirect(b64(bomb))
	if !errors.Is(err, ErrInflateLimit) {
		t.Fatalf("got %v, want ErrInflateLimit", err)
	}

	// Exactly at the limit is fine.
	if _, err := DecodeRedirect(b64(compress(t, "deflate", make([]byte, MaxInflated)))); err != nil {
		t.Errorf("at limit: %v", err)
	}
}
