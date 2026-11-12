package redact

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrOutputExists means the output file exists and replacing it was not
// requested.
var ErrOutputExists = errors.New("output file already exists")

// WriteFile writes data to out with 0600 permissions, atomically: it writes
// a temporary file in the same directory and renames it into place, so a
// failure at any point leaves no partial file behind and never damages an
// existing one.
//
// It refuses to write over in (the original capture is the only
// unredacted evidence), even through a symlink or hard link, and refuses
// to replace any other existing file unless force is set.
func WriteFile(out, in string, data []byte, force bool) error {
	inInfo, err := os.Stat(in)
	if err != nil {
		return fmt.Errorf("check input: %w", err)
	}
	if outInfo, err := os.Stat(out); err == nil {
		// os.SameFile compares device and inode, so it sees through
		// symlinks, hard links, and different spellings of the same path.
		if os.SameFile(inInfo, outInfo) {
			return fmt.Errorf("%s is the input file; refusing to overwrite it", out)
		}
		if outInfo.IsDir() {
			return fmt.Errorf("%s is a directory", out)
		}
		if !force {
			return fmt.Errorf("%s: %w; use --force to replace it", out, ErrOutputExists)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check output: %w", err)
	}

	// CreateTemp makes the file with 0600 permissions from the start, so
	// the redacted data is never readable by other users, not even briefly.
	tmp, err := os.CreateTemp(filepath.Dir(out), ".ssotrace-*.har.tmp")
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	tmpName := tmp.Name()
	done := false
	defer func() {
		if !done {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	// Flush to disk before the rename makes the file visible, so a crash
	// cannot leave a correctly named but empty file.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("set output permissions: %w", err)
	}
	if err := os.Rename(tmpName, out); err != nil {
		return fmt.Errorf("move output into place: %w", err)
	}
	done = true
	return nil
}
