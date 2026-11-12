package saml

import (
	"encoding/base64"
	"testing"

	"github.com/Josperdo/ssotrace/internal/testutil"
)

// FuzzParse feeds arbitrary bytes to the SAML parser, including signature
// verification. It must return a model or an error, never panic or hang.
func FuzzParse(f *testing.F) {
	idp := testutil.NewKeyPair(f, "idp.example.com")
	f.Add(testutil.Response(f, idp, testutil.DefaultResponseOptions()))
	o := testutil.DefaultResponseOptions()
	o.SignResponse = true
	f.Add(testutil.Response(f, idp, o))
	f.Add(testutil.AuthnRequest(f, testutil.DefaultAuthnRequestOptions()))
	f.Add([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status/></samlp:Response>`))
	f.Add([]byte(`<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = Parse(data, testutil.RefTime)
	})
}

// FuzzDecodeRedirect checks the base64 + DEFLATE decoder, which inflates
// attacker-chosen data and must respect MaxInflated.
func FuzzDecodeRedirect(f *testing.F) {
	req := testutil.RedirectURL(f, "https://idp.example.com/sso", testutil.AuthnRequest(f, testutil.DefaultAuthnRequestOptions()), "", nil)
	f.Add(req)
	f.Add(base64.StdEncoding.EncodeToString([]byte("<x/>")))
	f.Add("")
	f.Add("!!!!")

	f.Fuzz(func(t *testing.T, s string) {
		out, err := DecodeRedirect(s)
		if err == nil && len(out) > MaxInflated {
			t.Fatalf("inflated %d bytes, over the %d limit", len(out), MaxInflated)
		}
		_, _ = DecodePOST(s)
	})
}
