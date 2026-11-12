package redact

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/beevik/etree"

	"github.com/Josperdo/ssotrace/internal/har"
	"github.com/Josperdo/ssotrace/internal/saml"
	"github.com/Josperdo/ssotrace/internal/secret"
)

// Kind is a category of secret.
type Kind string

// Kinds of secret the scanner finds. They are ordered roughly by how much
// damage a leak does, which is the order the report lists them in.
const (
	KindCookie     Kind = "Session cookie"
	KindCredHeader Kind = "Credential header" //nolint:gosec // a category label, not a credential
	KindJWT        Kind = "JWT (token)"
	KindToken      Kind = "Token or code parameter" //nolint:gosec // a category label, not a credential
	KindPassword   Kind = "Password"
	KindSAML       Kind = "SAML signature or identity"
	KindEmail      Kind = "Email address"
	KindUnreadable Kind = "Unreadable content"
)

var kindOrder = []Kind{KindCookie, KindCredHeader, KindJWT, KindToken, KindPassword, KindSAML, KindEmail, KindUnreadable}

// Leak is one secret found in a HAR. It never holds the secret itself,
// only a preview, so a Leak is always safe to print.
type Leak struct {
	Kind    Kind   `json:"kind"`
	Entry   int    `json:"entry"`   // index into log.entries
	Where   string `json:"where"`   // e.g. "request header Authorization"
	Preview string `json:"preview"` // secret.Preview of the value
}

// tokenParams are parameter names whose value is a credential: holding it
// is enough to act as the user or the application.
var tokenParams = map[string]bool{
	"access_token": true, "id_token": true, "refresh_token": true, "code": true,
	"client_secret": true, "client_assertion": true, "assertion": true,
	"code_verifier": true, "device_code": true, "token": true, "SAMLart": true,
	"api_key": true, "apikey": true, "session_state": true,
}

// passwordParam matches form field names that hold passwords.
var passwordParam = regexp.MustCompile(`(?i)pass|pwd|secret`)

// credHeader matches header names that carry credentials. Authorization
// and Proxy-Authorization are the standard ones; the rest are common
// conventions for API keys and CSRF tokens.
var credHeader = regexp.MustCompile(`(?i)^(proxy-)?authorization$|token|secret|api-?key|x-csrf|x-xsrf|session`)

var (
	// A JWT is three base64url segments; the first two decode to JSON
	// objects, which is why they start with "eyJ" ("{\"").
	jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.([A-Za-z0-9_-]*)`)
	// A deliberately loose email pattern: over-matching is fine for a
	// leak scanner, missing an address is not.
	emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	// Token fields in JSON bodies, as token endpoints return them.
	jsonTokenField = regexp.MustCompile(`"(access_token|id_token|refresh_token|client_secret|password|code|device_code)"\s*:\s*"([^"]+)"`)
)

// Scan reports every secret it can find in h. It is used twice: by
// `ssotrace scan` on a capture as recorded, and on every redacted file
// before it is written, where any result at all aborts the write.
//
// It errs toward reporting: a false alarm costs a moment's reading, a
// missed secret could cost an account.
func Scan(h *har.HAR) []Leak {
	if h == nil {
		return nil
	}
	s := &scanner{seen: map[string]bool{}}
	// The log comment is free text: the redactor writes only its own summary
	// there, but a scan that skipped a field because "we wrote it" would not
	// be failing closed.
	s.idx = -1
	s.text("log comment", h.Log.Comment)
	for i := range h.Log.Entries {
		s.entry(i, &h.Log.Entries[i])
	}
	sort.SliceStable(s.leaks, func(a, b int) bool {
		return kindRank(s.leaks[a].Kind) < kindRank(s.leaks[b].Kind)
	})
	return s.leaks
}

func kindRank(k Kind) int {
	for i, o := range kindOrder {
		if o == k {
			return i
		}
	}
	return len(kindOrder)
}

type scanner struct {
	leaks []Leak
	idx   int // entry being scanned
	seen  map[string]bool
}

func (s *scanner) add(k Kind, where, value string) {
	// One value in one entry is one leak, even when two detectors see it
	// (a JWT in an access_token parameter matches both). The first,
	// most specific detector wins: parameters are checked before free text.
	key := fmt.Sprintf("%d\x00%s", s.idx, value)
	if s.seen[key] {
		return
	}
	s.seen[key] = true
	preview := secret.Preview(value)
	if k == KindPassword || k == KindEmail || identityTag(where) {
		preview = secret.Hidden(value)
	}
	s.leaks = append(s.leaks, Leak{Kind: k, Entry: s.idx, Where: where, Preview: preview})
}

func (s *scanner) entry(i int, e *har.Entry) {
	s.idx = i
	req, resp := &e.Request, &e.Response

	for _, c := range req.Cookies {
		if !isRedacted(c.Value) {
			s.add(KindCookie, "request cookie "+c.Name, c.Value)
		}
	}
	for _, c := range resp.Cookies {
		if !isRedacted(c.Value) {
			s.add(KindCookie, "response cookie "+c.Name, c.Value)
		}
	}
	s.headers("request", req.Headers)
	s.headers("response", resp.Headers)

	s.url("request URL", req.URL)
	if resp.RedirectURL != "" {
		s.url("redirect URL", resp.RedirectURL)
	}

	if req.PostData != nil {
		s.postData(req.PostData)
	}
	s.responseBody(&resp.Content)
}

// headers checks header values. Cookie headers are checked cookie by
// cookie; URL-carrying headers (Location, Referer, and HTTP/2 :path) are
// checked like URLs; everything else is searched for embedded tokens.
func (s *scanner) headers(side string, hs []har.NameValue) {
	for _, h := range hs {
		name := strings.ToLower(h.Name)
		where := side + " header " + h.Name
		switch {
		case name == "cookie" || name == "set-cookie":
			s.cookieHeader(where, h.Value)
		case credHeader.MatchString(h.Name):
			if !isRedacted(h.Value) {
				s.add(KindCredHeader, where, h.Value)
			}
		case name == "location" || name == "referer" || name == ":path":
			s.url(where, h.Value)
		default:
			s.text(where, h.Value)
		}
	}
}

// cookieHeader checks every name=value pair in a Cookie or Set-Cookie
// header. In Set-Cookie only the first pair is the cookie; the rest are
// attributes such as Path and SameSite, which are not secret.
func (s *scanner) cookieHeader(where, v string) {
	pairs := strings.Split(v, ";")
	if strings.HasSuffix(strings.ToLower(where), "set-cookie") {
		pairs = pairs[:1]
	}
	for _, p := range pairs {
		name, val, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok && !isRedacted(val) {
			s.add(KindCookie, where+" ("+name+")", val)
		}
	}
}

// url checks a URL's query string and fragment (implicit-flow tokens
// arrive in the fragment), then searches the whole URL, unescaped, for
// JWTs and email addresses.
func (s *scanner) url(where, raw string) {
	u, err := url.Parse(raw)
	if err == nil {
		s.params(where+" query", u.RawQuery, true)
		s.params(where+" fragment", u.Fragment, true)
		if u.User != nil {
			s.add(KindPassword, where+" (user info)", u.User.String())
		}
	}
	if un, err := url.QueryUnescape(raw); err == nil {
		raw = un
	}
	s.text(where, raw)
}

// params checks name=value pairs from a query string, fragment, or form.
func (s *scanner) params(where, encoded string, inURL bool) {
	if encoded == "" {
		return
	}
	vals, err := url.ParseQuery(encoded)
	if err != nil {
		// Fragments are not always name=value lists; nothing to check then.
		return
	}
	names := make([]string, 0, len(vals))
	for n := range vals {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, v := range vals[name] {
			s.param(where, name, v, inURL)
		}
	}
}

func (s *scanner) param(where, name, v string, inURL bool) {
	if isRedacted(v) {
		return
	}
	at := where + " " + name
	switch {
	case name == "SAMLResponse" || name == "SAMLRequest":
		s.samlParam(at, v, inURL)
	case tokenParams[name]:
		s.add(KindToken, at, v)
	case passwordParam.MatchString(name):
		s.add(KindPassword, at, v)
	default:
		s.text(at, v)
	}
}

// samlParam decodes a SAML message and checks the parts that identify the
// user or let it be replayed. A message that cannot be decoded cannot be
// shown to be safe, so it is reported.
func (s *scanner) samlParam(where, v string, redirect bool) {
	decode := saml.DecodePOST
	if redirect {
		decode = saml.DecodeRedirect
	}
	raw, err := decode(v)
	if err != nil {
		s.add(KindUnreadable, where+" (could not be decoded)", v)
		return
	}
	root, err := saml.ParseXML(raw)
	if err != nil {
		s.add(KindUnreadable, where+" (could not be parsed)", v)
		return
	}
	walk(root, func(el *etree.Element) {
		switch el.Tag {
		case "SignatureValue", "DigestValue":
			if t := allText(el); !isRedacted(t) {
				s.add(KindSAML, where+" "+el.Tag, t)
			}
		case "NameID", "AttributeValue":
			if t := allText(el); !isRedacted(t) {
				s.add(KindSAML, where+" "+el.Tag, t)
			}
		case "AuthnStatement":
			if idx := el.SelectAttrValue("SessionIndex", ""); !isRedacted(idx) {
				s.add(KindSAML, where+" SessionIndex", idx)
			}
		}
	})
}

func (s *scanner) postData(p *har.PostData) {
	for _, prm := range p.Params {
		v := prm.Value
		if un, err := url.QueryUnescape(v); err == nil {
			v = un
		}
		s.param("form field", prm.Name, v, false)
	}
	if p.Text == "" {
		return
	}
	if strings.Contains(strings.ToLower(p.MimeType), "x-www-form-urlencoded") || p.MimeType == "" {
		s.params("form field", p.Text, false)
		return
	}
	s.body("request body", p.Text)
}

func (s *scanner) responseBody(c *har.Content) {
	if c.Text == "" {
		return
	}
	b, err := c.Bytes()
	if err != nil {
		s.add(KindUnreadable, "response body (could not be decoded)", c.Text)
		return
	}
	s.body("response body", string(b))
}

// body searches a whole body: JSON token fields and auto-submitting SAML
// forms first, then the generic JWT and email search.
func (s *scanner) body(where, text string) {
	for _, m := range jsonTokenField.FindAllStringSubmatch(text, -1) {
		if !isRedacted(m[2]) {
			s.add(KindToken, where+" field "+m[1], m[2])
		}
	}
	if strings.Contains(text, "SAMLResponse") || strings.Contains(text, "SAMLRequest") {
		s.add(KindSAML, where+" (contains a SAML message)", text)
	}
	s.text(where, text)
}

// text searches free text for JWTs and email addresses.
func (s *scanner) text(where, t string) {
	for _, m := range jwtPattern.FindAllStringSubmatch(t, -1) {
		if m[1] != jwtSigMarker {
			s.add(KindJWT, where, m[0])
		}
	}
	for _, m := range emailPattern.FindAllString(t, -1) {
		if !strings.HasSuffix(strings.ToLower(m), "@"+maskDomain) {
			s.add(KindEmail, where, m)
		}
	}
}

// walk calls fn for el and every descendant element.
func walk(el *etree.Element, fn func(*etree.Element)) {
	fn(el)
	for _, c := range el.ChildElements() {
		walk(c, fn)
	}
}

// allText joins every text node under el, at any depth, skipping comments.
// It reads what canonicalization would sign, so text split by a comment
// ("alice@example.com<!---->.evil") is seen in full.
func allText(el *etree.Element) string {
	var b strings.Builder
	var rec func(*etree.Element)
	rec = func(e *etree.Element) {
		for _, tok := range e.Child {
			switch t := tok.(type) {
			case *etree.CharData:
				b.WriteString(t.Data)
			case *etree.Element:
				rec(t)
			}
		}
	}
	rec(el)
	return strings.TrimSpace(b.String())
}

// Summary counts leaks by kind, in report order.
func Summary(leaks []Leak) []KindCount {
	counts := map[Kind]int{}
	for _, l := range leaks {
		counts[l.Kind]++
	}
	var out []KindCount
	for _, k := range kindOrder {
		if counts[k] > 0 {
			out = append(out, KindCount{k, counts[k]})
		}
	}
	return out
}

// KindCount is one row of Summary.
type KindCount struct {
	Kind  Kind `json:"kind"`
	Count int  `json:"count"`
}

func (k KindCount) String() string { return fmt.Sprintf("%s: %d", k.Kind, k.Count) }

// identityTag reports whether a SAML leak location holds the user's
// identity (NameID, attribute values), whose prefix should not be shown.
func identityTag(where string) bool {
	return strings.HasSuffix(where, " NameID") || strings.HasSuffix(where, " AttributeValue")
}
