package oidc

import "testing"

// FuzzParse feeds arbitrary strings to the JWT parser. It must return a
// token or an error, never panic.
func FuzzParse(f *testing.F) {
	f.Add(token(rs256, `{"iss":"https://idp.example.com","aud":["a","b"],"exp":1768474800.25}`))
	f.Add(seg(`{"alg":"none"}`) + "." + seg(`{}`) + ".")
	f.Add("a.b.c.d.e")
	f.Add("")

	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Parse(s)
	})
}
