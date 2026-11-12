package flow

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Josperdo/ssotrace/internal/har"
	"github.com/Josperdo/ssotrace/internal/testutil"
)

// samlEntries builds HAR entries for a sequence of SAML steps. Each step is
// either an AuthnRequest ID ("req:<id>") or a Response answering an ID
// ("resp:<id>", or "resp:" for IdP-initiated).
func samlEntries(t *testing.T, idp *testutil.KeyPair, steps ...string) *har.HAR {
	t.Helper()
	var entries []har.Entry
	at := testutil.RefTime
	for _, step := range steps {
		kind, id, _ := strings.Cut(step, ":")
		at = at.Add(time.Second)
		switch kind {
		case "req":
			o := testutil.DefaultAuthnRequestOptions()
			o.ID = id
			u := testutil.RedirectURL(t, o.Destination, testutil.AuthnRequest(t, o), "", nil)
			entries = append(entries, testutil.GetEntry(t, u, at, 200))
		case "resp":
			o := testutil.DefaultResponseOptions()
			o.InResponseTo = id
			form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(testutil.Response(t, idp, o))}}
			entries = append(entries, testutil.PostFormEntry(o.Destination, form, at, 302))
		default:
			t.Fatalf("bad step %q", step)
		}
	}
	return testutil.NewHAR(entries...)
}

type flowShape struct {
	req, resp        string // request ID, response InResponseTo; "-" = side missing
	idpInit, unmatch bool
}

func shapeOf(f SAMLFlow) flowShape {
	s := flowShape{req: "-", resp: "-", idpInit: f.IDPInitiated, unmatch: f.UnmatchedInResponseTo}
	if f.Request != nil {
		s.req = f.Request.Message.AuthnRequest.ID
	}
	if f.Response != nil {
		s.resp = f.Response.Message.Response.InResponseTo
	}
	return s
}

func TestCorrelateSAML(t *testing.T) {
	idp := testutil.NewKeyPair(t, "idp.example.com")

	tests := []struct {
		name  string
		steps []string
		want  []flowShape
	}{
		{"sp-initiated", []string{"req:_a", "resp:_a"}, []flowShape{{req: "_a", resp: "_a"}}},
		{"idp-initiated", []string{"resp:"}, []flowShape{{req: "-", resp: "", idpInit: true}}},
		{"request never answered", []string{"req:_a"}, []flowShape{{req: "_a", resp: "-"}}},
		{"response to uncaptured request", []string{"resp:_zz"}, []flowShape{{req: "-", resp: "_zz", unmatch: true}}},
		{
			"two logins, answered out of order",
			[]string{"req:_a", "req:_b", "resp:_b", "resp:_a"},
			[]flowShape{{req: "_a", resp: "_a"}, {req: "_b", resp: "_b"}},
		},
		{
			"replayed response matches only once",
			[]string{"req:_a", "resp:_a", "resp:_a"},
			[]flowShape{{req: "_a", resp: "_a"}, {req: "-", resp: "_a", unmatch: true}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trace := TraceSAML(samlEntries(t, idp, tt.steps...))
			if len(trace.Flows) != len(tt.want) {
				t.Fatalf("flows = %d, want %d", len(trace.Flows), len(tt.want))
			}
			for i, want := range tt.want {
				if got := shapeOf(trace.Flows[i]); got != want {
					t.Errorf("flow %d = %+v, want %+v", i, got, want)
				}
			}
		})
	}
}

func TestTraceSAMLRecordsTransport(t *testing.T) {
	login := testutil.NewSAMLLogin(t, testutil.DefaultAuthnRequestOptions(), testutil.DefaultResponseOptions())
	trace := TraceSAML(login.HAR)
	if len(trace.Flows) != 1 {
		t.Fatalf("flows = %d", len(trace.Flows))
	}
	f := trace.Flows[0]

	req := f.Request
	if req.Binding != BindingRedirect || req.Method != "GET" || req.Entry != 0 || req.Param != "SAMLRequest" {
		t.Errorf("request transport = %+v", req)
	}
	if req.URL != "https://idp.example.com/saml/sso" {
		t.Errorf("request URL = %q (query must be dropped)", req.URL)
	}

	resp := f.Response
	if resp.Binding != BindingPOST || resp.Method != "POST" || resp.HTTPStatus != 302 || resp.Entry != 1 {
		t.Errorf("response transport = %+v", resp)
	}
	if resp.URL != "https://app.example.org/saml/acs" {
		t.Errorf("response URL = %q", resp.URL)
	}
	if resp.Time != "2026-01-15T10:00:01Z" {
		t.Errorf("response time = %q", resp.Time)
	}
	if !resp.Message.Response.Assertions[0].Verified {
		t.Error("assertion not verified at the HAR timestamp")
	}
}

func TestTraceSAMLBadMessages(t *testing.T) {
	const secret = "SUPERSECRETVALUE"
	form := url.Values{"SAMLResponse": {"!!" + secret}}
	h := testutil.NewHAR(
		testutil.PostFormEntry("https://app.example.org/saml/acs", form, testutil.RefTime, 400),
		testutil.GetEntry(t, "https://app.example.org/saml/acs?SAMLart=AAQAA"+secret, testutil.RefTime, 302),
	)
	trace := TraceSAML(h)
	if len(trace.Flows) != 0 || len(trace.Other) != 2 {
		t.Fatalf("flows = %d, other = %d", len(trace.Flows), len(trace.Other))
	}
	if bad := trace.Other[0]; bad.Error == "" || strings.Contains(bad.Error, secret) {
		t.Errorf("decode error = %q", bad.Error)
	}
	if art := trace.Other[1]; art.Binding != BindingArtifact || art.Message != nil || strings.Contains(art.URL, secret) {
		t.Errorf("artifact = %+v", art)
	}
}
