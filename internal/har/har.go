package har

import (
	"encoding/base64"
	"fmt"
	"time"
)

// The types below model the parts of HAR 1.2 that ssotrace reads
// (http://www.softwareishard.com/blog/har-12-spec/). Fields we never use,
// such as page timings and cache details, are left out on purpose: every
// modeled field is one more place where an unusual exporter could make
// decoding fail. Unknown fields, including browser extensions like Chrome's
// "_initiator", are ignored by encoding/json.

// HAR is the root object of a HAR file.
type HAR struct {
	Log Log `json:"log"`
}

// Log holds the capture metadata and every recorded request.
type Log struct {
	Version string   `json:"version"`
	Creator Creator  `json:"creator"`
	Browser *Creator `json:"browser,omitempty"` // optional; Chrome omits it
	Entries []Entry  `json:"entries"`
	Comment string   `json:"comment,omitempty"`
}

// Creator names the tool (or browser) that produced the file.
type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Entry is one HTTP request and its response.
type Entry struct {
	Pageref string `json:"pageref,omitempty"`
	// StartedDateTime is kept as the raw string. Exporters disagree on the
	// exact ISO 8601 layout, so parsing happens in Started, where a bad
	// timestamp affects only the rules that need it rather than failing
	// the whole file.
	StartedDateTime string   `json:"startedDateTime"`
	Time            float64  `json:"time"` // total milliseconds; may be fractional
	Request         Request  `json:"request"`
	Response        Response `json:"response"`
	Timings         Timings  `json:"timings"`
	ServerIPAddress string   `json:"serverIPAddress,omitempty"`
	Connection      string   `json:"connection,omitempty"`
	Comment         string   `json:"comment,omitempty"`
}

// Request is the request half of an Entry.
type Request struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []Cookie    `json:"cookies"`
	Headers     []NameValue `json:"headers"`
	QueryString []NameValue `json:"queryString"`
	// PostData is a pointer because "no body was captured" and "an empty
	// body was captured" mean different things, and HAR002 depends on
	// telling them apart.
	PostData    *PostData `json:"postData,omitempty"`
	HeadersSize int64     `json:"headersSize"` // -1 if unknown
	BodySize    int64     `json:"bodySize"`    // -1 if unknown
}

// Response is the response half of an Entry.
type Response struct {
	Status      int         `json:"status"` // 0 when the request never completed
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []Cookie    `json:"cookies"`
	Headers     []NameValue `json:"headers"`
	Content     Content     `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int64       `json:"headersSize"` // -1 if unknown
	BodySize    int64       `json:"bodySize"`    // -1 if unknown
}

// NameValue is a header or query string pair.
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Cookie is a request or response cookie.
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Expires  string `json:"expires,omitempty"` // ISO 8601; null in some exports
	HTTPOnly bool   `json:"httpOnly,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
}

// PostData is a captured request body.
type PostData struct {
	MimeType string `json:"mimeType"`
	// Params and Text are alternatives: exporters fill one or both. See
	// Request.FormParam for how ssotrace chooses between them.
	Params []Param `json:"params,omitempty"`
	Text   string  `json:"text,omitempty"`
}

// Param is one parsed field of a form body.
type Param struct {
	Name        string `json:"name"`
	Value       string `json:"value,omitempty"`
	FileName    string `json:"fileName,omitempty"`
	ContentType string `json:"contentType,omitempty"`
}

// Content is a captured response body.
type Content struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	// Encoding is "base64" when Text holds binary data, empty otherwise.
	Encoding string `json:"encoding,omitempty"`
}

// Timings breaks down where an entry's time went, in milliseconds. -1 means
// the phase did not apply or was not measured.
type Timings struct {
	Blocked float64 `json:"blocked,omitempty"`
	DNS     float64 `json:"dns,omitempty"`
	Connect float64 `json:"connect,omitempty"`
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
	SSL     float64 `json:"ssl,omitempty"`
}

// timestampLayouts are the startedDateTime forms seen in real exports, most
// common first. RFC 3339 covers both "Z" (Chrome, Safari) and "+01:00"
// (Firefox); the second covers tools that drop the colon in the offset.
var timestampLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999-0700",
}

// Started parses StartedDateTime.
func (e *Entry) Started() (time.Time, error) {
	for _, layout := range timestampLayouts {
		if t, err := time.Parse(layout, e.StartedDateTime); err == nil {
			return t, nil
		}
	}
	// The value is deliberately not echoed: it comes from an untrusted file
	// and could hold anything.
	return time.Time{}, fmt.Errorf("parse startedDateTime: not an ISO 8601 timestamp")
}

// Bytes returns the response body, decoding it if the exporter stored it as
// base64. An empty result means no body was captured (or it was empty).
//
// No extra size cap is needed here: base64 decoding only shrinks data, and
// the text already fit within the loader's file size limit.
func (c *Content) Bytes() ([]byte, error) {
	switch c.Encoding {
	case "":
		return []byte(c.Text), nil
	case "base64":
		b, err := base64.StdEncoding.DecodeString(c.Text)
		if err != nil {
			// Some tools drop the "=" padding; accept that rather than
			// rejecting an otherwise readable body.
			b, err = base64.RawStdEncoding.DecodeString(c.Text)
		}
		if err != nil {
			return nil, fmt.Errorf("decode base64 response content: %w", err)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("unsupported response content encoding %q", c.Encoding)
	}
}
