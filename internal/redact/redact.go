package redact

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Josperdo/ssotrace/internal/diagnose"
	"github.com/Josperdo/ssotrace/internal/har"
)

// Options controls a redaction.
type Options struct {
	// KeepBodies keeps response bodies instead of replacing them with a
	// stub. The leak scan still runs, so a body holding a secret still
	// stops the write.
	KeepBodies bool
	// Salt keys the hashes that mask identifiers. Leave it nil: a fresh
	// random salt is generated and never stored, so a masked value cannot
	// be reversed by hashing guesses. Tests set it to get stable output.
	Salt []byte
	// Comment is written to log.comment, e.g. a diagnosis summary.
	Comment string
}

// Redact returns a copy of h that is safe to share, built on an allowlist:
// the output contains only fields ssotrace understands, and within them
// only values known to be safe. Everything else is replaced with
// [redacted] or left out. h is not modified.
//
// What stays is what diagnosis needs: URLs without their secrets, HTTP
// statuses and timings, SAML messages with signatures and identities
// masked, and the names (never the values) of cookies and parameters.
//
// Redact does not decide whether its output is safe; the caller must run
// Scan on the result and refuse to write it if anything is found.
func Redact(h *har.HAR, opts Options) (*har.HAR, error) {
	salt := opts.Salt
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("generate salt: %w", err)
		}
	}
	r := &redactor{salt: salt, keepBodies: opts.KeepBodies}

	out := &har.HAR{Log: har.Log{
		Version: h.Log.Version,
		Creator: har.Creator{Name: r.scrub(h.Log.Creator.Name), Version: r.scrub(h.Log.Creator.Version)},
		Comment: opts.Comment,
		Entries: make([]har.Entry, 0, len(h.Log.Entries)),
	}}
	if b := h.Log.Browser; b != nil {
		out.Log.Browser = &har.Creator{Name: r.scrub(b.Name), Version: r.scrub(b.Version)}
	}
	for i := range h.Log.Entries {
		out.Log.Entries = append(out.Log.Entries, r.entry(&h.Log.Entries[i]))
	}
	return out, nil
}

type redactor struct {
	salt       []byte
	keepBodies bool
	at         time.Time // HAR time of the entry being redacted
}

// mask replaces an identifier with a salted hash. Equal inputs give equal
// outputs within one run, so correlation survives ("both messages are
// about the same user"), but with the salt discarded nobody can test a
// guess against the output. An email-shaped input keeps an email shape on
// a reserved domain, so format checks on the redacted file still pass.
func (r *redactor) mask(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	m := hmac.New(sha256.New, r.salt)
	m.Write([]byte(v))
	h := hex.EncodeToString(m.Sum(nil))[:12]
	if strings.Contains(v, "@") {
		return "u-" + h + "@" + maskDomain
	}
	return maskPrefix + h
}

func (r *redactor) entry(e *har.Entry) har.Entry {
	r.at, _ = e.Started()
	// Dropped on purpose: serverIPAddress (internal addresses), connection,
	// pageref (pages are not kept: their titles are URLs), and comment
	// (free text from whoever exported the file).
	return har.Entry{
		StartedDateTime: r.scrub(e.StartedDateTime),
		Time:            e.Time,
		Timings:         e.Timings,
		Request:         r.request(&e.Request),
		Response:        r.response(&e.Response),
	}
}

func (r *redactor) request(q *har.Request) har.Request {
	u, pairs := r.url(q.URL)
	out := har.Request{
		Method:      r.scrub(q.Method),
		URL:         u,
		HTTPVersion: r.scrub(q.HTTPVersion),
		Cookies:     r.cookies(q.Cookies),
		Headers:     r.headers(q.Headers),
		QueryString: pairs,
		HeadersSize: q.HeadersSize,
		BodySize:    q.BodySize,
	}
	if q.PostData != nil {
		out.PostData = r.postData(q.PostData)
	}
	return out
}

func (r *redactor) response(p *har.Response) har.Response {
	redirect := ""
	if p.RedirectURL != "" {
		redirect, _ = r.url(p.RedirectURL)
	}
	return har.Response{
		Status:      p.Status,
		StatusText:  r.scrub(p.StatusText),
		HTTPVersion: r.scrub(p.HTTPVersion),
		Cookies:     r.cookies(p.Cookies),
		Headers:     r.headers(p.Headers),
		Content:     r.content(&p.Content),
		RedirectURL: redirect,
		HeadersSize: p.HeadersSize,
		BodySize:    p.BodySize,
	}
}

// --- URLs and parameters ---

// url redacts a URL's query and fragment parameter by parameter, drops any
// user:password@, and keeps scheme, host, and path. It also returns the
// redacted query as HAR queryString pairs, in their original order.
func (r *redactor) url(raw string) (string, []har.NameValue) {
	u, err := url.Parse(raw)
	if err != nil {
		return Redacted, []har.NameValue{}
	}
	u.User = nil
	// Scheme, host, and path are kept because diagnosis compares them, but
	// some apps put tokens or email addresses in paths (magic links,
	// /users/alice@example.com). Those parts are scrubbed.
	u.Host = r.scrub(u.Host)
	u.Path, u.RawPath = r.scrub(u.Path), ""
	// "Opaque" URLs (scheme:anything, like mailto:alice@example.com) keep
	// everything after the colon here instead of in Path.
	u.Opaque = r.scrub(u.Opaque)
	query, pairs := r.query(u.RawQuery, true)
	u.RawQuery = query
	if u.Fragment != "" {
		// Implicit-flow tokens arrive in the fragment as a query string.
		frag, _ := r.query(u.Fragment, false)
		u.Fragment, u.RawFragment = "", ""
		if frag != "" {
			// Set via the raw form so the already-encoded pairs are kept.
			return u.String() + "#" + frag, pairs
		}
	}
	return u.String(), pairs
}

// query redacts an encoded name=value list, keeping the original order
// (url.Values would sort it). inQuery selects the Redirect binding for
// SAML parameters.
func (r *redactor) query(raw string, inQuery bool) (string, []har.NameValue) {
	pairs := []har.NameValue{}
	if raw == "" {
		return "", pairs
	}
	var parts []string
	for _, kv := range strings.Split(raw, "&") {
		if kv == "" {
			continue
		}
		name, val, hasEq := strings.Cut(kv, "=")
		name, err1 := url.QueryUnescape(name)
		val, err2 := url.QueryUnescape(val)
		if err1 != nil || err2 != nil {
			// Can't read it, so can't keep it.
			parts = append(parts, url.QueryEscape(Redacted))
			continue
		}
		red := r.param(name, val, inQuery)
		name = r.scrub(name)
		pairs = append(pairs, har.NameValue{Name: name, Value: red})
		if hasEq {
			parts = append(parts, url.QueryEscape(name)+"="+url.QueryEscape(red))
		} else {
			parts = append(parts, url.QueryEscape(name))
		}
	}
	return strings.Join(parts, "&"), pairs
}

// keepParams are OAuth, OIDC, and SAML parameters whose values describe the
// request rather than authorize it. Diagnosis reads them; none is a
// credential.
var keepParams = map[string]bool{
	"client_id": true, "response_type": true, "response_mode": true, "scope": true,
	"prompt": true, "max_age": true, "acr_values": true, "grant_type": true,
	"code_challenge_method": true, "display": true, "ui_locales": true,
	"error_uri": true, "SigAlg": true,
}

// param redacts one parameter value. The default is [redacted]: a
// parameter is kept only if it is known to be safe or can be cleaned.
func (r *redactor) param(name, v string, inQuery bool) string {
	switch {
	case v == "":
		return ""
	case name == "SAMLRequest" || name == "SAMLResponse":
		return r.samlParam(v, inQuery)
	case name == "redirect_uri" || name == "post_logout_redirect_uri":
		u, _ := r.url(v)
		return u
	case name == "error":
		// Standard OAuth error values are a fixed vocabulary; anything else
		// is free text and could hold anything.
		if diagnose.IsOAuthError(v) {
			return v
		}
		return Redacted
	case name == "error_description":
		return keepCodesOnly(v)
	case name == "id_token" || name == "access_token" || name == "logout_token":
		return r.jwt(v)
	case keepParams[name]:
		return r.scrub(v)
	default:
		return Redacted
	}
}

// keepCodesOnly reduces free text to the IdP error codes in it, which is
// what HAR004 needs; the rest can name the user or their tenant.
func keepCodesOnly(v string) string {
	c := &har.Content{MimeType: "text/plain", Text: v}
	codes := diagnose.ErrorCodesInBody(c)
	if len(codes) == 0 {
		return Redacted
	}
	return strings.Join(codes, " ") + " " + Redacted
}

// --- headers and cookies ---

// keepHeaders are headers whose values are about the transport, not the
// user: safe to keep verbatim and often useful (content types, caching,
// security policy). Every other header keeps its name and loses its value.
var keepHeaders = map[string]bool{
	"accept": true, "accept-encoding": true, "accept-language": true, "accept-ranges": true,
	"access-control-allow-credentials": true, "access-control-allow-headers": true,
	"access-control-allow-methods": true, "access-control-allow-origin": true,
	"access-control-expose-headers": true, "access-control-max-age": true,
	"access-control-request-headers": true, "access-control-request-method": true,
	"age": true, "cache-control": true, "connection": true, "content-encoding": true,
	"content-language": true, "content-length": true, "content-type": true, "date": true,
	"expires": true, "host": true, "keep-alive": true, "last-modified": true, "origin": true,
	"pragma": true, "referrer-policy": true, "server": true, "strict-transport-security": true,
	"transfer-encoding": true, "upgrade-insecure-requests": true, "user-agent": true, "vary": true,
	"x-content-type-options": true, "x-frame-options": true, "x-xss-protection": true,
	":authority": true, ":method": true, ":scheme": true, ":status": true,
	"sec-fetch-dest": true, "sec-fetch-mode": true, "sec-fetch-site": true, "sec-fetch-user": true,
	"sec-ch-ua": true, "sec-ch-ua-mobile": true, "sec-ch-ua-platform": true,
}

// urlHeaders carry a URL whose query may hold secrets.
var urlHeaders = map[string]bool{"location": true, "referer": true, "content-location": true, ":path": true}

func (r *redactor) headers(hs []har.NameValue) []har.NameValue {
	out := make([]har.NameValue, 0, len(hs))
	for _, h := range hs {
		name := strings.ToLower(h.Name)
		v := h.Value
		switch {
		case name == "cookie":
			v = r.cookieHeader(v)
		case name == "set-cookie":
			v = r.setCookie(v)
		case name == "authorization" || name == "proxy-authorization":
			// Keep the scheme ("Bearer", "Basic"): it says what kind of
			// credential was sent, which is diagnostic and not secret.
			scheme, _, _ := strings.Cut(strings.TrimSpace(v), " ")
			v = Redacted
			if scheme != "" && !strings.ContainsAny(scheme, "=.") && len(scheme) < 20 {
				v = Redacted + " (" + scheme + ")"
			}
		case urlHeaders[name]:
			if name == ":path" {
				// A path, not a full URL: give it a base to parse against.
				full, _ := r.url("https://h" + v)
				v = strings.TrimPrefix(full, "https://h")
			} else {
				v, _ = r.url(v)
			}
		case keepHeaders[name]:
			v = r.scrub(v)
		default:
			v = Redacted
		}
		out = append(out, har.NameValue{Name: r.scrub(h.Name), Value: v})
	}
	return out
}

// cookies keeps each cookie's name and attributes (Path, Domain,
// Secure, HttpOnly, Expires), which explain session problems, and drops
// its value, which is the credential.
func (r *redactor) cookies(cs []har.Cookie) []har.Cookie {
	out := make([]har.Cookie, 0, len(cs))
	for _, c := range cs {
		c.Value = Redacted
		c.Name, c.Path, c.Domain, c.Expires = r.scrub(c.Name), r.scrub(c.Path), r.scrub(c.Domain), r.scrub(c.Expires)
		out = append(out, c)
	}
	return out
}

// cookieHeader turns "a=1; b=2" into "a=[redacted]; b=[redacted]".
func (r *redactor) cookieHeader(v string) string {
	var parts []string
	for _, p := range strings.Split(v, ";") {
		name, _, _ := strings.Cut(strings.TrimSpace(p), "=")
		if name != "" {
			parts = append(parts, r.scrub(name)+"="+Redacted)
		}
	}
	return strings.Join(parts, "; ")
}

// setCookie redacts the value of each cookie in a Set-Cookie header
// and keeps its attributes. Some exporters put several cookies in one
// header separated by newlines.
func (r *redactor) setCookie(v string) string {
	var lines []string
	for _, line := range strings.Split(v, "\n") {
		attrs := strings.Split(line, ";")
		name, _, _ := strings.Cut(strings.TrimSpace(attrs[0]), "=")
		attrs[0] = r.scrub(name) + "=" + Redacted
		for i := 1; i < len(attrs); i++ {
			attrs[i] = r.scrub(attrs[i])
		}
		lines = append(lines, strings.Join(attrs, ";"))
	}
	return strings.Join(lines, "\n")
}

// --- bodies ---

func (r *redactor) postData(p *har.PostData) *har.PostData {
	out := &har.PostData{MimeType: r.scrub(p.MimeType)}
	mime := strings.ToLower(p.MimeType)
	isForm := strings.Contains(mime, "x-www-form-urlencoded") || mime == ""
	switch {
	case isForm && p.Text != "":
		out.Text, _ = r.query(p.Text, false)
		out.Params = formParams(out.Text)
	case isForm && len(p.Params) > 0:
		// Params only: rebuild a text body from them so both stay in step.
		var parts []string
		for _, prm := range p.Params {
			v, err := url.QueryUnescape(prm.Value)
			if err != nil {
				v = Redacted
			}
			parts = append(parts, url.QueryEscape(prm.Name)+"="+url.QueryEscape(r.param(prm.Name, v, false)))
		}
		out.Text = strings.Join(parts, "&")
		out.Params = formParams(out.Text)
	case p.Text != "" || len(p.Params) > 0:
		// JSON, multipart, or anything else: there is no safe subset to
		// keep. The body is marked rather than emptied, so HAR002 (body
		// missing) does not mistake redaction for a broken capture.
		out.Text = Redacted
	}
	return out
}

// formParams lists an encoded form as HAR params, values still encoded,
// the way browsers record them.
func formParams(encoded string) []har.Param {
	var ps []har.Param
	for _, kv := range strings.Split(encoded, "&") {
		name, val, _ := strings.Cut(kv, "=")
		if n, err := url.QueryUnescape(name); err == nil && n != "" {
			ps = append(ps, har.Param{Name: n, Value: val})
		}
	}
	return ps
}

// content replaces a response body with a short stub, unless bodies are
// kept. The stub keeps the IdP error codes the body contained, in a form
// HAR004 still recognizes, because an error code is often the most useful
// clue in the whole capture.
func (r *redactor) content(c *har.Content) har.Content {
	out := har.Content{Size: c.Size, MimeType: r.scrub(c.MimeType)}
	if r.keepBodies {
		out.Text, out.Encoding = c.Text, c.Encoding
		return out
	}
	codes := diagnose.ErrorCodesInBody(c)
	if len(codes) == 0 {
		return out
	}
	if strings.Contains(strings.ToLower(c.MimeType), "json") {
		stub := `{"ssotrace":"body removed by redaction","codes":"` + strings.Join(codes, " ") + `"`
		for _, code := range codes {
			if diagnose.IsOAuthError(code) {
				stub += `,"error":"` + code + `"`
				break
			}
		}
		out.Text = stub + "}"
		return out
	}
	out.Text = "[ssotrace: body removed by redaction; IdP error codes: " + strings.Join(codes, " ") + "]"
	return out
}

// scrub cleans a string the redactor otherwise keeps verbatim (a URL path,
// a safe header value, a parameter name). It applies the scanner's two
// free-text detectors as removers: JWTs become [redacted], and email
// addresses get the same salted mask as NameIDs. Without this, a value in a
// kept field would make the leak scan stop the write.
func (r *redactor) scrub(s string) string {
	if s == "" {
		return s
	}
	s = jwtPattern.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasSuffix(m, "."+jwtSigMarker) {
			return m // already redacted by us
		}
		return Redacted
	})
	return emailPattern.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasSuffix(strings.ToLower(m), "@"+maskDomain) {
			return m
		}
		return r.mask(m)
	})
}
