// Command sp is a minimal SAML service provider for the ssotrace lab.
//
// INTENTIONALLY INSECURE. LOCAL TESTING ONLY. It does not verify signatures,
// check audience, or enforce time limits, because its only job is to produce
// real-shaped SAML traffic for a browser to capture as a HAR. Judging whether
// that traffic is valid is ssotrace's job, not this program's.
//
// It speaks two bindings:
//   - HTTP-Redirect for the AuthnRequest it sends to the IdP, and
//   - HTTP-POST for the Response the IdP sends back to /saml/acs.
package main

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

// maxFormBytes bounds the ACS form body. Real SAML Responses are a few
// kilobytes; nothing legitimate needs more.
const maxFormBytes = 1 << 20

type config struct {
	listen    string // address to listen on
	baseURL   string // URL the browser uses to reach this SP
	idpSSOURL string // IdP endpoint that receives the AuthnRequest
}

func main() {
	var c config
	flag.StringVar(&c.listen, "listen", "127.0.0.1:8081", "address to listen on")
	flag.StringVar(&c.baseURL, "base-url", "http://127.0.0.1:8081", "URL the browser uses to reach this SP")
	flag.StringVar(&c.idpSSOURL, "idp-sso-url", "http://127.0.0.1:8080/realms/ssotrace-lab/protocol/saml", "IdP single sign-on URL")
	flag.Parse()

	srv := &http.Server{
		Addr:              c.listen,
		Handler:           c.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("lab SP listening on %s (browse to %s)", c.listen, c.baseURL)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Print(err)
		os.Exit(1)
	}
}

// entityID is how the IdP knows this SP. Keycloak uses it as the client ID,
// so it must match "clientId" in lab/realm/ssotrace-lab.json.
func (c config) entityID() string { return c.baseURL + "/saml/metadata" }
func (c config) acsURL() string   { return c.baseURL + "/saml/acs" }

func (c config) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", c.home)
	mux.HandleFunc("GET /login", c.login)
	mux.HandleFunc("POST /saml/acs", c.acs)
	mux.HandleFunc("GET /saml/metadata", c.metadata)
	return mux
}

var homePage = template.Must(template.New("home").Parse(`<!doctype html>
<title>ssotrace lab SP</title>
<h1>ssotrace lab SP</h1>
<p>Open DevTools → Network, tick <b>Preserve log</b>, then:</p>
<p><a href="/login">Log in with Keycloak (SP-initiated)</a></p>
`))

func (c config) home(w http.ResponseWriter, _ *http.Request) {
	render(w, homePage, nil)
}

// login starts SP-initiated SSO: build an AuthnRequest and send the browser
// to the IdP with it in the query string (HTTP-Redirect binding).
func (c config) login(w http.ResponseWriter, r *http.Request) {
	id, err := newID()
	if err != nil {
		http.Error(w, "generate request ID", http.StatusInternalServerError)
		return
	}
	req := authnRequest{
		XMLNS:        "urn:oasis:names:tc:SAML:2.0:protocol",
		ID:           id,
		Version:      "2.0",
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		Destination:  c.idpSSOURL,
		ACSURL:       c.acsURL(),
		Binding:      "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Issuer:       issuer{XMLNS: "urn:oasis:names:tc:SAML:2.0:assertion", Value: c.entityID()},
	}
	encoded, err := encodeRedirect(req)
	if err != nil {
		http.Error(w, "encode AuthnRequest", http.StatusInternalServerError)
		return
	}

	q := url.Values{}
	q.Set("SAMLRequest", encoded)
	// RelayState is opaque to the IdP and comes back unchanged with the
	// Response. Real SPs use it to remember where the user was going.
	q.Set("RelayState", "/")
	http.Redirect(w, r, c.idpSSOURL+"?"+q.Encode(), http.StatusFound)
}

type authnRequest struct {
	XMLName      xml.Name `xml:"samlp:AuthnRequest"`
	XMLNS        string   `xml:"xmlns:samlp,attr"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr"`
	ACSURL       string   `xml:"AssertionConsumerServiceURL,attr"`
	Binding      string   `xml:"ProtocolBinding,attr"`
	Issuer       issuer
}

type issuer struct {
	XMLName xml.Name `xml:"saml:Issuer"`
	XMLNS   string   `xml:"xmlns:saml,attr"`
	Value   string   `xml:",chardata"`
}

// encodeRedirect applies the HTTP-Redirect binding encoding: raw DEFLATE
// (no zlib header), then standard base64. The caller URL-encodes it.
func encodeRedirect(v any) (string, error) {
	raw, err := xml.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", fmt.Errorf("deflate: %w", err)
	}
	if _, err := fw.Write(raw); err != nil {
		return "", fmt.Errorf("deflate: %w", err)
	}
	if err := fw.Close(); err != nil {
		return "", fmt.Errorf("deflate: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// samlResponse picks out the fields worth showing. encoding/xml matches on
// local names, so the saml/samlp prefixes Keycloak uses do not matter here.
type samlResponse struct {
	Destination  string `xml:"Destination,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`
	Issuer       string `xml:"Issuer"`
	Status       struct {
		Code struct {
			Value string `xml:"Value,attr"`
		} `xml:"StatusCode"`
	} `xml:"Status"`
	Assertion struct {
		NameID     string `xml:"Subject>NameID"`
		Conditions struct {
			NotBefore    string   `xml:"NotBefore,attr"`
			NotOnOrAfter string   `xml:"NotOnOrAfter,attr"`
			Audiences    []string `xml:"AudienceRestriction>Audience"`
		} `xml:"Conditions"`
		Attributes []struct {
			Name   string   `xml:"Name,attr"`
			Values []string `xml:"AttributeValue"`
		} `xml:"AttributeStatement>Attribute"`
	} `xml:"Assertion"`
}

var acsPage = template.Must(template.New("acs").Parse(`<!doctype html>
<title>ssotrace lab SP: response received</title>
<h1>SAML Response received</h1>
<p><b>Signature NOT verified.</b> This lab SP never checks signatures, audience, or times.</p>
<table border="1" cellpadding="4">
<tr><th>Status</th><td>{{.Status.Code.Value}}</td></tr>
<tr><th>Issuer</th><td>{{.Issuer}}</td></tr>
<tr><th>Destination</th><td>{{.Destination}}</td></tr>
<tr><th>InResponseTo</th><td>{{.InResponseTo}}</td></tr>
<tr><th>NameID</th><td>{{.Assertion.NameID}}</td></tr>
<tr><th>Audience</th><td>{{range .Assertion.Conditions.Audiences}}{{.}} {{end}}</td></tr>
<tr><th>NotBefore</th><td>{{.Assertion.Conditions.NotBefore}}</td></tr>
<tr><th>NotOnOrAfter</th><td>{{.Assertion.Conditions.NotOnOrAfter}}</td></tr>
{{range .Assertion.Attributes}}<tr><th>{{.Name}}</th><td>{{range .Values}}{{.}} {{end}}</td></tr>
{{end}}</table>
<p>Now export the HAR from DevTools into <code>lab/captures/</code>. <a href="/">Back</a></p>
`))

// acs is the Assertion Consumer Service: the IdP's auto-submitting form
// POSTs the base64 Response here (HTTP-POST binding).
func (c config) acs(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLResponse"))
	if err != nil {
		http.Error(w, "SAMLResponse is not valid base64", http.StatusBadRequest)
		return
	}
	var resp samlResponse
	if err := xml.Unmarshal(raw, &resp); err != nil {
		http.Error(w, "SAMLResponse is not valid XML", http.StatusBadRequest)
		return
	}
	render(w, acsPage, resp)
}

// metadata publishes this SP's SAML metadata. Keycloak can import it, and it
// documents the entity ID and ACS URL in the standard format.
func (c config) metadata(w http.ResponseWriter, _ *http.Request) {
	md := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false" WantAssertionsSigned="true">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
`, xmlEscape(c.entityID()), xmlEscape(c.acsURL()))
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write([]byte(md))
}

func render(w http.ResponseWriter, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		log.Printf("render %s: %v", t.Name(), err)
	}
}

// newID returns a SAML ID. IDs must be valid XML names, which cannot start
// with a digit, hence the underscore prefix.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "_" + hex.EncodeToString(b), nil
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
