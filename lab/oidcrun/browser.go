package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Fixed lab endpoints, the same ones lab/sp/oidc.html uses.
const (
	issuer      = "http://127.0.0.1:8080/realms/ssotrace-lab"
	clientID    = "lab-spa"
	redirectURI = "http://127.0.0.1:8081/oidc/callback"
	appOrigin   = "http://127.0.0.1:8081"
	spaPage     = "http://127.0.0.1:8081/oidc/"
	maxHops     = 10
)

// browser stands in for a person in a fresh private window: its own
// cookie jar, every request recorded, and redirects followed one hop at a
// time so each hop is its own HAR entry, as in DevTools.
type browser struct {
	client   *http.Client
	rec      *recorder
	user     string
	password string
	// fragment is the fragment of the last redirect followed. A browser
	// never sends it to the server, so it only shows in Location.
	fragment string
}

func newBrowser(user, password string) (*browser, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("cookie jar: %w", err)
	}
	rec := &recorder{next: http.DefaultTransport}
	return &browser{
		client: &http.Client{
			Transport: rec,
			Jar:       jar,
			Timeout:   20 * time.Second,
			// Follow redirects by hand, so each hop is recorded and a
			// redirect to the app's callback can stop the walk.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		rec:      rec,
		user:     user,
		password: password,
	}, nil
}

// page is what the browser ended up showing.
type page struct {
	url    *url.URL
	status int
	body   string
}

// navigate loads rawURL and follows redirects until a page renders.
func (b *browser) navigate(method, rawURL string, form url.Values) (*page, error) {
	for hop := 0; hop < maxHops; hop++ {
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", rawURL, err)
		}
		if u.Fragment != "" {
			b.fragment = u.Fragment
		}
		u.Fragment = ""

		var req *http.Request
		if method == http.MethodPost {
			req, err = http.NewRequest(method, u.String(), strings.NewReader(form.Encode()))
			if err == nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Origin", u.Scheme+"://"+u.Host)
			}
		} else {
			req, err = http.NewRequest(method, u.String(), nil)
		}
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		resp, err := b.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", method, u.Redacted(), err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", u.Redacted(), err)
		}
		loc := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode > 399 || loc == "" {
			return &page{url: u, status: resp.StatusCode, body: string(body)}, nil
		}
		next, err := u.Parse(loc)
		if err != nil {
			return nil, fmt.Errorf("parse redirect: %w", err)
		}
		// A redirect after a POST becomes a GET, as in a browser.
		method, form, rawURL = http.MethodGet, nil, next.String()
	}
	return nil, fmt.Errorf("more than %d redirects", maxHops)
}

var (
	formRE   = regexp.MustCompile(`(?is)<form\b[^>]*\baction="([^"]*)"[^>]*>(.*?)</form>`)
	inputRE  = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	attrRE   = regexp.MustCompile(`(?is)\b(name|value|type)="([^"]*)"`)
	errorsRE = regexp.MustCompile(`(?is)id="kc-error-message".*?<p[^>]*>(.*?)</p>`)
)

// htmlForm is a form found on a page: where it posts and its hidden fields.
type htmlForm struct {
	action string
	fields url.Values
	submit []string // names of submit buttons
	body   string
}

// findForm returns the first form whose markup contains marker.
func findForm(p *page, marker string) (*htmlForm, bool) {
	for _, m := range formRE.FindAllStringSubmatch(p.body, -1) {
		if !strings.Contains(m[0], marker) {
			continue
		}
		f := &htmlForm{action: html.UnescapeString(m[1]), fields: url.Values{}, body: m[2]}
		for _, in := range inputRE.FindAllString(m[2], -1) {
			attrs := map[string]string{}
			for _, a := range attrRE.FindAllStringSubmatch(in, -1) {
				attrs[strings.ToLower(a[1])] = html.UnescapeString(a[2])
			}
			switch attrs["type"] {
			case "hidden":
				f.fields.Set(attrs["name"], attrs["value"])
			case "submit":
				f.submit = append(f.submit, attrs["name"])
			}
		}
		return f, true
	}
	return nil, false
}

// signIn walks from the authorization request to wherever Keycloak
// sends the browser: the app's callback, or an error page. consent says
// how to answer a consent screen.
func (b *browser) signIn(authURL string, acceptConsent bool) (*page, error) {
	p, err := b.navigate(http.MethodGet, authURL, nil)
	if err != nil {
		return nil, err
	}
	if f, ok := findForm(p, `name="password"`); ok {
		f.fields.Set("username", b.user)
		f.fields.Set("password", b.password)
		if p, err = b.navigate(http.MethodPost, resolve(p.url, f.action), f.fields); err != nil {
			return nil, err
		}
	}
	if f, ok := findForm(p, `name="accept"`); ok {
		if acceptConsent {
			f.fields.Set("accept", "Yes")
		} else {
			f.fields.Set("cancel", "No")
		}
		if p, err = b.navigate(http.MethodPost, resolve(p.url, f.action), f.fields); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// pageError returns Keycloak's error-page message, if the page is one.
func pageError(p *page) string {
	if m := errorsRE.FindStringSubmatch(p.body); m != nil {
		return strings.TrimSpace(html.UnescapeString(m[1]))
	}
	return ""
}

// redeem is the SPA's fetch() to the token endpoint: a cross-origin POST
// carrying the page's Origin.
func (b *browser) redeem(form url.Values) (int, error) {
	req, err := http.NewRequest(http.MethodPost, issuer+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return 0, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", appOrigin)
	resp, err := b.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("token request: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func resolve(base *url.URL, ref string) string {
	u, err := base.Parse(ref)
	if err != nil {
		return ref
	}
	return u.String()
}

func randomString() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error
	return base64.RawURLEncoding.EncodeToString(b)
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
