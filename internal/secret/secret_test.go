package secret

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestPreview(t *testing.T) {
	// Synthetic JWT-shaped value: header {"alg":"RS256"}, empty claims, fake signature.
	const fakeJWT = "eyJhbGciOiJSUzI1NiJ9.e30.ZmFrZS1zaWduYXR1cmUtZm9yLXRlc3Rz"

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "[redacted] (0 chars)"},
		{"one char", "x", "[redacted] (1 chars)"},
		{"short password", "hunter2", "[redacted] (7 chars)"},
		{"exactly 8 is hidden", "12345678", "[redacted] (8 chars)"},
		{"9 chars shows prefix", "123456789", "123456… (9 chars)"},
		{"jwt shaped", fakeJWT, "eyJhbG… (57 chars)"},
		{"unicode short is hidden", "pässwörd", "[redacted] (8 chars)"},
		{"unicode prefix not split", "日本語のパスワードです", "日本語のパス… (11 chars)"},
		{"emoji counted as runes", "🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑", "🔑🔑🔑🔑🔑🔑… (10 chars)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Preview(tt.in)
			if got != tt.want {
				t.Errorf("Preview(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("Preview(%q) returned invalid UTF-8: %q", tt.in, got)
			}
		})
	}
}

// TestPreviewNeverRevealsFullSecret guards the core promise directly:
// whatever the input, the output must not contain the whole secret.
func TestPreviewNeverRevealsFullSecret(t *testing.T) {
	// Single-char input is "z" because "[redacted]" itself contains letters
	// like "a", which would make the check falsely fail.
	inputs := []string{"z", "abcdefgh", "abcdefghi", "eyJhbGciOiJSUzI1NiJ9.e30.c2ln", "日本語のパスワードです"}
	for _, in := range inputs {
		if strings.Contains(Preview(in), in) {
			t.Errorf("Preview(%q) contains the full input", in)
		}
	}
}
