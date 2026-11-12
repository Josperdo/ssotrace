package redact

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "capture.har")
	if err := os.WriteFile(in, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "link.har")
	if err := os.Symlink(in, symlink); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(dir, "hard.har")
	if err := os.Link(in, hardlink); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(dir, "existing.har")
	if err := os.WriteFile(existing, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		out     string
		force   bool
		wantErr string
	}{
		{"new file", filepath.Join(dir, "new.har"), false, ""},
		{"input itself", in, true, "is the input file"},
		{"symlink to input", symlink, true, "is the input file"},
		{"hard link to input", hardlink, true, "is the input file"},
		{"existing without --force", existing, false, "--force"},
		{"existing with --force", existing, true, ""},
		{"directory", dir, true, "is a directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WriteFile(tt.out, in, []byte("redacted"), tt.force)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(tt.out)
			if string(got) != "redacted" {
				t.Errorf("content = %q", got)
			}
			info, _ := os.Stat(tt.out)
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("permissions = %o, want 600", perm)
			}
		})
	}

	if got, _ := os.ReadFile(in); string(got) != "original" {
		t.Errorf("input changed to %q", got)
	}
	if err := WriteFile(existing, in, nil, false); !errors.Is(err, ErrOutputExists) {
		t.Errorf("error = %v, want ErrOutputExists", err)
	}
	// No temporary files are left behind, whatever happened above.
	matches, _ := filepath.Glob(filepath.Join(dir, ".ssotrace-*"))
	if len(matches) != 0 {
		t.Errorf("temporary files left behind: %v", matches)
	}
}

// TestWriteFileFailureLeavesNothing: when the directory cannot be written,
// there is no output and no temporary file.
func TestWriteFileFailureLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "capture.har")
	if err := os.WriteFile(in, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "missing-subdir", "out.har")
	if err := WriteFile(out, in, []byte("y"), false); err == nil {
		t.Fatal("write into a missing directory succeeded")
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("output exists after a failed write")
	}
}
