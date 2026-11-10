package har

import (
	"mime"
	"net/url"
	"strings"
)

// Header returns the first request header named name. Header names are
// case-insensitive in HTTP, and exporters disagree on case: HTTP/2 captures
// use "content-type", HTTP/1.1 captures often use "Content-Type".
func (r *Request) Header(name string) (string, bool) {
	return headerValue(r.Headers, name)
}

// Header returns the first response header named name, ignoring case.
func (r *Response) Header(name string) (string, bool) {
	return headerValue(r.Headers, name)
}

func headerValue(headers []NameValue, name string) (string, bool) {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value, true
		}
	}
	return "", false
}

// QueryParam returns the first query parameter named name, decoded.
// Parameter names are case-sensitive ("SAMLRequest" is not "samlrequest").
//
// It reads the request URL rather than the queryString array. Every exporter
// writes the URL, its encoding is defined by the URL standard, and some
// exporters leave queryString empty or store its values still
// percent-encoded.
func (r *Request) QueryParam(name string) (string, bool) {
	u, err := url.Parse(r.URL)
	if err != nil {
		return "", false
	}
	// ParseQuery keeps every well-formed pair even when it reports an error
	// for a malformed one, so the error is deliberately ignored.
	values, _ := url.ParseQuery(u.RawQuery)
	return first(values, name)
}

// FormParam returns the first form field named name from the request body,
// decoded. It returns false when there is no body or the field is absent.
//
// When the exporter saved the raw body text, that is parsed: it is exactly
// what the browser sent. The params array is used only when the text is
// missing, because exporters disagree on whether params values are
// percent-encoded.
func (r *Request) FormParam(name string) (string, bool) {
	p := r.PostData
	if p == nil {
		return "", false
	}
	if p.Text != "" {
		if !isFormBody(p.MimeType) {
			return "", false
		}
		values, _ := url.ParseQuery(p.Text) // partial results are still useful; see QueryParam
		return first(values, name)
	}
	for _, param := range p.Params {
		if param.Name == name {
			return decodeParamValue(param.Value), true
		}
	}
	return "", false
}

// isFormBody reports whether a body with this MIME type should be parsed as
// application/x-www-form-urlencoded. An empty type is accepted because some
// exporters omit it; parsing a non-form body that way finds no SSO fields,
// so the mistake is harmless.
func isFormBody(mimeType string) bool {
	if mimeType == "" {
		return true
	}
	mt, _, err := mime.ParseMediaType(mimeType)
	return err == nil && mt == "application/x-www-form-urlencoded"
}

// decodeParamValue normalizes a params-array value. Some exporters store
// values percent-encoded ("abc%2B%3D"), others already decoded ("abc+=").
// A "%" is taken to mean the value is still encoded. That is always right
// for base64 SAML messages and OAuth codes, which never contain a literal
// "%". A free-form field such as RelayState could, and might be decoded
// twice; that is one more reason FormParam prefers the raw text.
func decodeParamValue(v string) string {
	if !strings.Contains(v, "%") {
		return v
	}
	decoded, err := url.QueryUnescape(v)
	if err != nil {
		return v
	}
	return decoded
}

func first(values url.Values, name string) (string, bool) {
	vs, ok := values[name]
	if !ok || len(vs) == 0 {
		return "", false
	}
	return vs[0], true
}
