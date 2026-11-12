package diagnose

import (
	"bytes"
	"testing"

	"github.com/Josperdo/ssotrace/internal/flow"
	"github.com/Josperdo/ssotrace/internal/har"
	"github.com/Josperdo/ssotrace/internal/testutil"
)

// FuzzDiagnose runs every rule on arbitrary HARs. Rules read deep into
// parsed SAML and URLs, so this is where an unchecked index or nil would
// show up as a crash on a crafted file.
func FuzzDiagnose(f *testing.F) {
	login := testutil.NewSAMLLogin(f, testutil.DefaultAuthnRequestOptions(), testutil.DefaultResponseOptions())
	f.Add(testutil.MarshalHAR(f, login.HAR))
	f.Add([]byte(`{"log":{"entries":[{"request":{"method":"GET","url":"https://a.example/?SAMLResponse=x&code=1&state=2"},"response":{"status":302}}]}}`))

	reg, err := DefaultRules()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		h, err := har.Decode(bytes.NewReader(data), 1<<20)
		if err != nil {
			return
		}
		ctx := Context{HAR: h, SAML: flow.TraceSAML(h), ClockSkew: DefaultClockSkew}
		_ = Run(ctx, reg)
	})
}
