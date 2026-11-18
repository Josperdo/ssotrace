package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Josperdo/ssotrace/internal/testutil"
)

func TestLoadJWKS(t *testing.T) {
	kp := testutil.NewKeyPair(t, "idp.example.com")
	dir := t.TempDir()

	ks, err := loadJWKS(writeFile(t, dir, "keys.json", string(testutil.RSAJWKS(t, "k1", &kp.Key.PublicKey))))
	if err != nil || len(ks.Keys) != 1 {
		t.Fatalf("loadJWKS = %+v, %v", ks, err)
	}

	const secret = "SUPERSECRETVALUE"
	private := `{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","d":"` + secret + `"}]}`
	_, err = loadJWKS(writeFile(t, dir, "private.json", private))
	if err == nil || !strings.Contains(err.Error(), "private or symmetric") || strings.Contains(err.Error(), secret) {
		t.Errorf("private key file: error = %v", err)
	}
	if _, err := loadJWKS(dir + "/missing.json"); err == nil || !strings.HasPrefix(err.Error(), "--jwks:") {
		t.Errorf("missing file: error = %v", err)
	}
}

func TestCheckFetchURL(t *testing.T) {
	tests := []struct {
		url string
		ok  bool
	}{
		{"https://idp.example.com/realms/lab/protocol/openid-connect/certs", true},
		{"http://localhost:8080/realms/lab/protocol/openid-connect/certs", true},
		{"http://127.0.0.1:8080/certs", true},
		{"http://[::1]/certs", true},
		{"http://idp.example.com/certs", false}, // keys over plain http could be swapped
		{"ftp://idp.example.com/certs", false},
		{"file:///etc/passwd", false},
		{"/relative/path", false},
	}
	for _, tt := range tests {
		if err := checkFetchURL(tt.url); (err == nil) != tt.ok {
			t.Errorf("checkFetchURL(%q) = %v, want ok=%v", tt.url, err, tt.ok)
		}
	}
}

func TestCheckFetchRedirect(t *testing.T) {
	req := func(raw string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	tests := []struct {
		name     string
		from, to string
		hops     int
		wantErr  string
	}{
		{name: "https to https", from: "https://idp.example.com/certs", to: "https://keys.example.com/certs"},
		{name: "local http to local http", from: "http://127.0.0.1:8080/certs", to: "http://localhost:8080/certs"},
		{name: "local http up to https", from: "http://127.0.0.1:8080/certs", to: "https://idp.example.com/certs"},
		{
			name: "https down to local http", from: "https://idp.example.com/certs", to: "http://127.0.0.1:9000/admin",
			wantErr: "https to plain http",
		},
		{name: "local http to remote http", from: "http://127.0.0.1/certs", to: "http://idp.example.com/certs", wantErr: "must use https"},
		{name: "too many", from: "https://idp.example.com/a", to: "https://idp.example.com/b", hops: maxFetchRedirects, wantErr: "too many"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			via := []*http.Request{req(tt.from)}
			for len(via) < max(tt.hops, 1) {
				via = append([]*http.Request{req(tt.from)}, via...)
			}
			err := checkFetchRedirect(req(tt.to), via)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("err = %v, want allowed", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestFetchJWKS(t *testing.T) {
	kp := testutil.NewKeyPair(t, "idp.example.com")
	keys := testutil.RSAJWKS(t, "k1", &kp.Key.PublicKey)
	var gotUA string
	mux := http.NewServeMux()
	mux.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_, _ = w.Write(keys)
	})
	mux.HandleFunc("/missing", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "SUPERSECRETVALUE", http.StatusNotFound)
	})
	mux.HandleFunc("/huge", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte(" "), 2<<20))
	})
	mux.HandleFunc("/downgrade", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://idp.example.com/certs", http.StatusFound)
	})
	srv := httptest.NewServer(mux) // plain http on 127.0.0.1, which the loopback rule allows
	defer srv.Close()

	ks, err := fetchJWKS(srv.URL+"/certs", "v9.9.9")
	if err != nil || len(ks.Keys) != 1 {
		t.Fatalf("fetchJWKS = %+v, %v", ks, err)
	}
	if gotUA != "ssotrace/v9.9.9" {
		t.Errorf("User-Agent = %q", gotUA)
	}

	for path, want := range map[string]string{
		"/missing":   "HTTP 404",
		"/huge":      "over the",
		"/downgrade": "must use https",
	} {
		_, err := fetchJWKS(srv.URL+path, "v")
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "SUPERSECRETVALUE") {
			t.Errorf("%s: error = %v, want containing %q and no body content", path, err, want)
		}
	}
}

func TestDiagnoseJWKSFlags(t *testing.T) {
	login := testutil.NewOIDCLogin(t, testutil.DefaultOIDCLoginOptions())
	dir := t.TempDir()
	harPath := writeFile(t, dir, "login.har", string(testutil.MarshalHAR(t, login.HAR)))
	keysPath := writeFile(t, dir, "keys.json", string(testutil.RSAJWKS(t, "lab-key-1", &login.Key.Key.PublicKey)))

	tests := []struct {
		name     string
		args     []string
		wantCode int
		stderr   string
	}{
		{"valid key file", []string{"--jwks", keysPath}, ExitOK, ""},
		{"key file is not a key set", []string{"--jwks", harPath}, ExitUsage, "--jwks:"},
		{"plain http to another host", []string{"--fetch-jwks", "http://idp.example.com/certs"}, ExitUsage, "must use https"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(append([]string{"diagnose", harPath}, tt.args...), &stdout, &stderr, BuildInfo{})
			if code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d; stderr = %q", code, tt.wantCode, stderr.String())
			}
			checkStream(t, "stderr", stderr.String(), tt.stderr)
		})
	}
}
