package har

import (
	"testing"
	"time"
)

func TestHeader(t *testing.T) {
	r := Request{Headers: []NameValue{
		{Name: "content-type", Value: "text/html"},
		{Name: "X-Dup", Value: "first"},
		{Name: "x-dup", Value: "second"},
	}}
	tests := []struct {
		name   string
		want   string
		wantOK bool
	}{
		{"Content-Type", "text/html", true},
		{"CONTENT-TYPE", "text/html", true},
		{"x-dup", "first", true}, // first match wins
		{"Authorization", "", false},
	}
	for _, tt := range tests {
		got, ok := r.Header(tt.name)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("Header(%q) = %q, %v; want %q, %v", tt.name, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestQueryParam(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		param  string
		want   string
		wantOK bool
	}{
		{"decoded", "https://idp.example.org/sso?SAMLRequest=abc%2B%2F%3D", "SAMLRequest", "abc+/=", true},
		{"case-sensitive name", "https://idp.example.org/sso?SAMLRequest=x", "samlrequest", "", false},
		{"first of repeated", "https://a.example.com/?state=1&state=2", "state", "1", true},
		{"empty value present", "https://a.example.com/?code=", "code", "", true},
		{"absent", "https://a.example.com/?a=1", "code", "", false},
		{"no query", "https://a.example.com/", "code", "", false},
		{"bad pair keeps good ones", "https://a.example.com/?bad=%zz&code=ok", "code", "ok", true},
		{"unparseable URL", "://bad", "code", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Request{URL: tt.url}
			got, ok := r.QueryParam(tt.param)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("QueryParam(%q) = %q, %v; want %q, %v", tt.param, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestFormParam(t *testing.T) {
	const form = "application/x-www-form-urlencoded"
	tests := []struct {
		name   string
		post   *PostData
		want   string
		wantOK bool
	}{
		{"no body", nil, "", false},
		{"text", &PostData{MimeType: form, Text: "code=a%2Bb&state=s"}, "a+b", true},
		{"text with charset", &PostData{MimeType: form + "; charset=UTF-8", Text: "code=x"}, "x", true},
		{"text without mime type", &PostData{Text: "code=x"}, "x", true},
		{"json body is not a form", &PostData{MimeType: "application/json", Text: `{"code":"x"}`}, "", false},
		{"text preferred over params", &PostData{MimeType: form, Text: "code=fromtext", Params: []Param{{Name: "code", Value: "fromparams"}}}, "fromtext", true},
		{"params encoded", &PostData{MimeType: form, Params: []Param{{Name: "code", Value: "a%2Bb%3D"}}}, "a+b=", true},
		{"params decoded", &PostData{MimeType: form, Params: []Param{{Name: "code", Value: "a+b="}}}, "a+b=", true},
		{"params absent", &PostData{MimeType: form, Params: []Param{{Name: "other", Value: "1"}}}, "", false},
		{"params bad escape kept", &PostData{MimeType: form, Params: []Param{{Name: "code", Value: "100%"}}}, "100%", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Request{PostData: tt.post}
			got, ok := r.FormParam("code")
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("FormParam = %q, %v; want %q, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestStarted(t *testing.T) {
	want := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		in      string
		wantErr bool
	}{
		{"2026-01-15T10:00:00Z", false},
		{"2026-01-15T10:00:00.000Z", false},
		{"2026-01-15T11:00:00.000+01:00", false},
		{"2026-01-15T11:00:00.000+0100", false},
		{"", true},
		{"yesterday", true},
	}
	for _, tt := range tests {
		e := Entry{StartedDateTime: tt.in}
		got, err := e.Started()
		if (err != nil) != tt.wantErr {
			t.Errorf("Started(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && !got.Equal(want) {
			t.Errorf("Started(%q) = %v, want %v", tt.in, got, want)
		}
	}
}

func TestContentBytes(t *testing.T) {
	tests := []struct {
		name    string
		c       Content
		want    string
		wantErr bool
	}{
		{"plain", Content{Text: "hello"}, "hello", false},
		{"empty", Content{}, "", false},
		{"base64", Content{Text: "aGVsbG8=", Encoding: "base64"}, "hello", false},
		{"base64 unpadded", Content{Text: "aGVsbG8", Encoding: "base64"}, "hello", false},
		{"bad base64", Content{Text: "!!!", Encoding: "base64"}, "", true},
		{"unknown encoding", Content{Text: "x", Encoding: "rot13"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.c.Bytes()
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if string(got) != tt.want {
				t.Errorf("Bytes = %q, want %q", got, tt.want)
			}
		})
	}
}
