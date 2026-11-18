package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// The HAR 1.2 subset this runner writes. It is a separate module, so it
// cannot import ssotrace's internal/har; that is deliberate, because the
// point is to produce a file the way a browser would, not the way
// ssotrace expects.
type harFile struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string     `json:"version"`
	Creator nameVer    `json:"creator"`
	Entries []harEntry `json:"entries"`
}

type nameVer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Timings         harTimings  `json:"timings"`
}

type harRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []nameValue `json:"cookies"`
	Headers     []nameValue `json:"headers"`
	QueryString []nameValue `json:"queryString"`
	PostData    *postData   `json:"postData,omitempty"`
	HeadersSize int64       `json:"headersSize"`
	BodySize    int64       `json:"bodySize"`
}

type postData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []nameValue `json:"cookies"`
	Headers     []nameValue `json:"headers"`
	Content     content     `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int64       `json:"headersSize"`
	BodySize    int64       `json:"bodySize"`
}

type content struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
}

type nameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harTimings struct {
	Send float64 `json:"send"`
	Wait float64 `json:"wait"`
}

// maxBody bounds what the recorder keeps of one response. Keycloak's pages
// are a few kilobytes; this only guards against a runaway answer.
const maxBody = 4 << 20

// recorder is an http.RoundTripper that writes every exchange into a HAR,
// as a browser's DevTools would with "Preserve log" on.
type recorder struct {
	next    http.RoundTripper
	mu      sync.Mutex
	entries []harEntry
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	var reqBody []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		reqBody = b
		req.Body = io.NopCloser(bytes.NewReader(b))
	}
	start := time.Now()
	resp, err := r.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	_ = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	elapsed := float64(time.Since(start).Microseconds()) / 1000

	e := harEntry{
		StartedDateTime: start.UTC().Format(time.RFC3339Nano),
		Time:            elapsed,
		Request: harRequest{
			Method:      req.Method,
			URL:         req.URL.String(),
			HTTPVersion: "HTTP/1.1",
			Cookies:     []nameValue{},
			Headers:     headers(req.Header),
			QueryString: query(req.URL),
			HeadersSize: -1,
			BodySize:    int64(len(reqBody)),
		},
		Response: harResponse{
			Status:      resp.StatusCode,
			StatusText:  http.StatusText(resp.StatusCode),
			HTTPVersion: "HTTP/1.1",
			Cookies:     []nameValue{},
			Headers:     headers(resp.Header),
			Content:     content{Size: int64(len(body)), MimeType: resp.Header.Get("Content-Type"), Text: string(body)},
			RedirectURL: resp.Header.Get("Location"),
			HeadersSize: -1,
			BodySize:    int64(len(body)),
		},
		Timings: harTimings{Wait: elapsed},
	}
	if reqBody != nil {
		e.Request.PostData = &postData{MimeType: req.Header.Get("Content-Type"), Text: string(reqBody)}
	}
	r.mu.Lock()
	r.entries = append(r.entries, e)
	r.mu.Unlock()
	return resp, nil
}

// write saves the recording with 0600 permissions: it holds real lab
// tokens, cookies, and alice's password.
func (r *recorder) write(path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := harFile{Log: harLog{Version: "1.2", Creator: nameVer{Name: "ssotrace-lab-oidcrun", Version: "1"}, Entries: r.entries}}
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return fmt.Errorf("encode HAR: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func headers(h http.Header) []nameValue {
	out := []nameValue{}
	for name, values := range h {
		for _, v := range values {
			out = append(out, nameValue{Name: name, Value: v})
		}
	}
	return out
}

func query(u *url.URL) []nameValue {
	out := []nameValue{}
	for name, values := range u.Query() {
		for _, v := range values {
			out = append(out, nameValue{Name: name, Value: v})
		}
	}
	return out
}
