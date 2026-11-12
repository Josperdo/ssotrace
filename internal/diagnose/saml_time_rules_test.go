package diagnose

import (
	"bytes"
	"testing"
	"time"

	"github.com/Josperdo/ssotrace/internal/testutil"
)

// In samlCtx the browser posts the first Response at RefTime + 1s. The
// default assertion is valid from RefTime - 1m to RefTime + 5m.

func TestSAML006ValidityWindow(t *testing.T) {
	ref := testutil.RefTime
	runRuleCases(t, validityWindow{}, []ruleCase{
		{"inside the window", []login{normal}, Pass, ""},
		{"expired long ago", []login{{resp: func(o *testutil.ResponseOptions) {
			o.NotOnOrAfter = ref.Add(-10 * time.Minute)
		}}}, Fail, "10 minutes 1 second"},
		{"expired within tolerance", []login{{resp: func(o *testutil.ResponseOptions) {
			o.NotOnOrAfter = ref.Add(-1 * time.Minute)
		}}}, Warn, "within clock-skew tolerance"},
		{"idp clock ahead", []login{{resp: func(o *testutil.ResponseOptions) {
			o.IssueInstant = ref.Add(10 * time.Minute)
			o.NotBefore = ref.Add(9 * time.Minute)
			o.NotOnOrAfter = ref.Add(15 * time.Minute)
		}}}, Fail, "IdP is at least 9 minutes 59 seconds ahead"},
		{"unreadable timestamp", []login{{mutate: func(b []byte) []byte {
			return bytes.Replace(b, []byte(`NotBefore="2026-01-15T09:59:00Z"`), []byte(`NotBefore="yesterday"`), 1)
		}}}, Warn, "yesterday"},
	})
}

// TestSAML006SkewSetting: the same minute-late assertion is a WARN under
// the default tolerance and a FAIL when the user asks for a strict check.
func TestSAML006SkewSetting(t *testing.T) {
	ctx := samlCtx(t, login{resp: func(o *testutil.ResponseOptions) {
		o.NotOnOrAfter = testutil.RefTime.Add(-1 * time.Minute)
	}})
	for _, tc := range []struct {
		skew time.Duration
		want Severity
	}{
		{DefaultClockSkew, Warn},
		{30 * time.Second, Fail},
		{0, Fail},
	} {
		ctx.ClockSkew = tc.skew
		if f := only(t, validityWindow{}, ctx); f.Severity != tc.want {
			t.Errorf("skew %v: severity = %v, want %v", tc.skew, f.Severity, tc.want)
		}
	}
}

func TestSAML009CertExpiry(t *testing.T) {
	ref := testutil.RefTime
	key := func(from, until time.Time) *testutil.KeyPair {
		return testutil.NewKeyPairValid(t, "idp.example.com", from, until)
	}
	runRuleCases(t, certExpiry{}, []ruleCase{
		{"valid for a year", []login{normal}, Pass, ""},
		{"expired", []login{{idp: key(ref.AddDate(-2, 0, 0), ref.AddDate(0, 0, -3))}}, Warn, "had expired"},
		{"expires in 10 days", []login{{idp: key(ref.AddDate(-1, 0, 0), ref.AddDate(0, 0, 10))}}, Warn, "10 days"},
		{"not yet valid", []login{{idp: key(ref.AddDate(0, 0, 1), ref.AddDate(1, 0, 0))}}, Warn, "not yet valid"},
	})

	// One certificate signing both the Response and the assertion is one
	// problem, so it is reported once.
	ctx := samlCtx(t, login{
		idp:  key(ref.AddDate(-2, 0, 0), ref.AddDate(0, 0, -3)),
		resp: func(o *testutil.ResponseOptions) { o.SignResponse = true },
	})
	if got := (certExpiry{}).Check(ctx); len(got) != 1 {
		t.Errorf("findings = %d, want 1 for one certificate", len(got))
	}
}
