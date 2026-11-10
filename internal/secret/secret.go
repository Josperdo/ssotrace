// Package secret provides helpers for showing secret values safely.
//
// Every token, cookie, signature, auth code, or password that reaches user
// output must go through Preview. A short prefix plus a length is enough to
// tell two values apart in a diagnosis without making either one usable.
package secret

import (
	"fmt"
	"unicode/utf8"
)

const (
	// prefixLen is how many leading characters Preview reveals.
	prefixLen = 6
	// minRevealLen is the shortest value that gets a prefix. At or below
	// this length, six characters would expose most of the secret (a short
	// PIN or password could be guessed from the rest), so nothing is shown.
	minRevealLen = 8
)

// Preview returns a display-safe stand-in for s.
//
//	Preview("eyJhbGciOiJSUzI1NiJ9.e30.c2ln") == "eyJhbG… (29 chars)"
//	Preview("hunter2")                       == "[redacted] (7 chars)"
//
// Lengths and prefixes count runes, not bytes, so a multi-byte UTF-8
// character is never cut in half and the length matches what a person sees.
func Preview(s string) string {
	n := utf8.RuneCountInString(s)
	if n <= minRevealLen {
		return fmt.Sprintf("[redacted] (%d chars)", n)
	}
	prefix := []rune(s)[:prefixLen]
	return fmt.Sprintf("%s… (%d chars)", string(prefix), n)
}
