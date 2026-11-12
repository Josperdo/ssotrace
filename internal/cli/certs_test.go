package cli

import (
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Josperdo/ssotrace/internal/testutil"
)

func TestLoadCerts(t *testing.T) {
	a := testutil.NewKeyPair(t, "old.example.com")
	b := testutil.NewKeyPair(t, "new.example.com")
	pemOf := func(kp *testutil.KeyPair) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kp.Cert.Raw}))
	}
	const secret = "SUPERSECRETVALUE"

	tests := []struct {
		name    string
		content string
		want    int    // certificates loaded; 0 = expect an error
		wantErr string // substring
	}{
		{"one PEM", pemOf(a), 1, ""},
		{"rollover bundle", pemOf(a) + pemOf(b), 2, ""},
		{"bare base64 from metadata", base64.StdEncoding.EncodeToString(a.Cert.Raw)[:40] + "\n" + base64.StdEncoding.EncodeToString(a.Cert.Raw)[40:], 1, ""},
		{"private key refused", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", 0, `"PRIVATE KEY" block`},
		{"garbage", "not base64! " + secret, 0, "neither a PEM certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "idp.pem")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			certs, err := loadCerts(path)
			if tt.want == 0 {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error %q leaks file content", err)
				}
				return
			}
			if err != nil || len(certs) != tt.want {
				t.Fatalf("got %d certs, err %v; want %d", len(certs), err, tt.want)
			}
		})
	}
}
