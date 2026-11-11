package testutil

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Josperdo/ssotrace/internal/har"
)

// GetEntry returns a HAR entry for a browser GET of rawURL, with the query
// string listed the way browsers record it.
func GetEntry(t testing.TB, rawURL string, started time.Time, status int) har.Entry {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	var qs []har.NameValue
	for _, pair := range strings.Split(u.RawQuery, "&") {
		name, value, _ := strings.Cut(pair, "=")
		if name != "" {
			// Browsers disagree on whether queryString values are decoded;
			// fixtures record them decoded, as Chrome does.
			v, err := url.QueryUnescape(value)
			if err != nil {
				t.Fatalf("query value for %s: %v", name, err)
			}
			qs = append(qs, har.NameValue{Name: name, Value: v})
		}
	}
	e := baseEntry(started, status)
	e.Request.Method = "GET"
	e.Request.URL = rawURL
	e.Request.QueryString = qs
	e.Request.BodySize = 0
	return e
}

// PostFormEntry returns a HAR entry for a browser form POST to rawURL, such
// as the IdP's auto-submitting form delivering a SAMLResponse.
func PostFormEntry(rawURL string, form url.Values, started time.Time, status int) har.Entry {
	body := form.Encode()
	params := make([]har.Param, 0, len(form))
	// Sorted so the same form always marshals to the same bytes; map order is
	// random in Go.
	for _, name := range slices.Sorted(maps.Keys(form)) {
		for _, v := range form[name] {
			params = append(params, har.Param{Name: name, Value: url.QueryEscape(v)})
		}
	}
	e := baseEntry(started, status)
	e.Request.Method = "POST"
	e.Request.URL = rawURL
	e.Request.Headers = []har.NameValue{{Name: "Content-Type", Value: "application/x-www-form-urlencoded"}}
	e.Request.PostData = &har.PostData{
		MimeType: "application/x-www-form-urlencoded",
		Params:   params,
		Text:     body,
	}
	e.Request.BodySize = int64(len(body))
	return e
}

func baseEntry(started time.Time, status int) har.Entry {
	return har.Entry{
		StartedDateTime: started.UTC().Format(time.RFC3339Nano),
		Time:            42,
		Request: har.Request{
			HTTPVersion: "HTTP/1.1",
			Cookies:     []har.Cookie{},
			Headers:     []har.NameValue{},
			QueryString: []har.NameValue{},
			HeadersSize: -1,
		},
		Response: har.Response{
			Status:      status,
			StatusText:  "",
			HTTPVersion: "HTTP/1.1",
			Cookies:     []har.Cookie{},
			Headers:     []har.NameValue{},
			Content:     har.Content{MimeType: "text/html"},
			HeadersSize: -1,
			BodySize:    0,
		},
		Timings: har.Timings{Send: 1, Wait: 40, Receive: 1},
	}
}

// NewHAR wraps entries in a HAR 1.2 log from a synthetic creator.
func NewHAR(entries ...har.Entry) *har.HAR {
	return &har.HAR{Log: har.Log{
		Version: "1.2",
		Creator: har.Creator{Name: "ssotrace testutil", Version: "1"},
		Entries: entries,
	}}
}

// MarshalHAR serializes h the way a browser export would be written.
func MarshalHAR(t testing.TB, h *har.HAR) []byte {
	t.Helper()
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		t.Fatalf("marshal HAR: %v", err)
	}
	return b
}

// SAMLLogin is a complete SP-initiated SAML login, as a browser would record
// it, plus the pieces a test may want to assert against.
type SAMLLogin struct {
	HAR          *har.HAR
	IDP          *KeyPair // signed the Response
	ResponseXML  []byte   // the Response before base64 encoding
	AuthnRequest []byte   // the AuthnRequest before deflate + base64
}

// NewSAMLLogin builds the two-step SP-initiated flow:
//  1. GET to the IdP carrying the AuthnRequest (HTTP-Redirect binding), and
//  2. POST to the SP's ACS carrying the signed Response (HTTP-POST binding).
//
// The IdP's login page in between carries no SAML and is left out.
func NewSAMLLogin(t testing.TB, req AuthnRequestOptions, resp ResponseOptions) *SAMLLogin {
	t.Helper()
	idp := NewKeyPair(t, "idp.example.com")
	reqXML := AuthnRequest(t, req)
	respXML := Response(t, idp, resp)

	redirect := RedirectURL(t, req.Destination, reqXML, "/", nil)
	form := url.Values{
		"SAMLResponse": {base64.StdEncoding.EncodeToString(respXML)},
		"RelayState":   {"/"},
	}
	h := NewHAR(
		GetEntry(t, redirect, req.IssueInstant, 200),
		PostFormEntry(resp.Destination, form, resp.IssueInstant.Add(time.Second), 302),
	)
	return &SAMLLogin{HAR: h, IDP: idp, ResponseXML: respXML, AuthnRequest: reqXML}
}
