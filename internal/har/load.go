package har

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// DefaultMaxBytes is the largest HAR file Load accepts unless the caller
// raises it. Real SSO captures are a few megabytes; 256 MiB leaves plenty of
// room while keeping a crafted file from exhausting memory.
const DefaultMaxBytes int64 = 256 << 20

var (
	// ErrTooLarge means the input exceeded the size limit.
	ErrTooLarge = errors.New("file too large")
	// ErrNotHAR means the input is readable but is not a HAR document.
	ErrNotHAR = errors.New("not a HAR file")
)

// Load reads and decodes the HAR file at path, refusing files larger than
// maxBytes.
func Load(path string, maxBytes int64) (*HAR, error) {
	f, err := os.Open(path) // #nosec G304 -- reading a user-chosen file is this tool's job
	if err != nil {
		return nil, err // already reads "open <path>: <reason>"
	}
	defer func() { _ = f.Close() }() // read-only: a close error cannot lose data

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory, not a HAR file", path)
	}
	// Fast path: reject an oversized regular file before reading a byte.
	// Decode enforces the same limit while reading, which also covers pipes
	// and files that grow after this check.
	if info.Mode().IsRegular() && info.Size() > maxBytes {
		return nil, fmt.Errorf("%s: %w (%s, limit %s)", path, ErrTooLarge, FormatBytes(info.Size()), FormatBytes(maxBytes))
	}

	h, err := Decode(f, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return h, nil
}

// Decode reads a HAR document from r, refusing input longer than maxBytes.
//
// It streams: entries are decoded one at a time with json.Decoder.Token, so
// peak memory is the decoded entries plus one entry's worth of buffer, not
// the whole file twice over (raw bytes and decoded structs).
func Decode(r io.Reader, maxBytes int64) (*HAR, error) {
	// Allow one byte past the limit so "exactly at the limit" and "over the
	// limit" can be told apart after decoding.
	limited := &io.LimitedReader{R: r, N: maxBytes + 1}
	br := bufio.NewReader(limited)

	if err := checkPrefix(br); err != nil {
		return nil, err
	}

	h, err := decodeHAR(json.NewDecoder(br))
	// Check the limit before the decode error: hitting the limit cuts the
	// JSON short, and "file too large" explains that better than "truncated".
	if limited.N <= 0 {
		return nil, fmt.Errorf("%w (limit %s)", ErrTooLarge, FormatBytes(maxBytes))
	}
	if err != nil {
		return nil, err
	}
	return h, nil
}

// checkPrefix handles the two non-JSON prefixes people actually feed in: a
// UTF-8 byte order mark (written by some Windows tools), which is skipped,
// and gzip compression, which gets a clear error instead of "invalid
// character".
func checkPrefix(br *bufio.Reader) error {
	head, _ := br.Peek(3) // a short or empty file is reported by the decoder
	switch {
	case bytes.HasPrefix(head, []byte{0xEF, 0xBB, 0xBF}):
		_, _ = br.Discard(3)
	case bytes.HasPrefix(head, []byte{0x1F, 0x8B}):
		return fmt.Errorf("%w: the file is gzip-compressed; decompress it first", ErrNotHAR)
	}
	return nil
}

func decodeHAR(dec *json.Decoder) (*HAR, error) {
	if err := expectDelim(dec, '{'); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: the file is empty", ErrNotHAR)
		}
		if errors.Is(err, ErrNotHAR) {
			return nil, err // describe() already said "not a HAR file"
		}
		return nil, fmt.Errorf("%w: top level: %w", ErrNotHAR, err)
	}

	var h HAR
	sawLog := false
	for dec.More() {
		key, err := readKey(dec)
		if err != nil {
			return nil, err
		}
		if key != "log" {
			if err := skipValue(dec); err != nil {
				return nil, err
			}
			continue
		}
		// A second "log" would silently replace or merge with the first.
		// Real exporters never write one, so treat it as hostile input.
		if sawLog {
			return nil, fmt.Errorf("%w: duplicate \"log\" object", ErrNotHAR)
		}
		sawLog = true
		if err := decodeLog(dec, &h.Log); err != nil {
			return nil, fmt.Errorf("log: %w", err)
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return nil, describe(err)
	}
	if !sawLog {
		return nil, fmt.Errorf("%w: missing \"log\" object", ErrNotHAR)
	}
	// A valid file ends here. Anything else means concatenated or corrupted
	// input, which we refuse rather than guess about.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: unexpected data after the HAR object", ErrNotHAR)
	}
	return &h, nil
}

func decodeLog(dec *json.Decoder, log *Log) error {
	if err := expectDelim(dec, '{'); err != nil {
		return err
	}
	sawEntries := false
	for dec.More() {
		key, err := readKey(dec)
		if err != nil {
			return err
		}
		switch key {
		case "entries":
			if sawEntries {
				return fmt.Errorf("duplicate \"entries\" array")
			}
			sawEntries = true
			err = decodeEntries(dec, &log.Entries)
		case "version":
			err = decodeField(dec, key, &log.Version)
		case "creator":
			err = decodeField(dec, key, &log.Creator)
		case "browser":
			err = decodeField(dec, key, &log.Browser)
		case "comment":
			err = decodeField(dec, key, &log.Comment)
		default:
			err = skipValue(dec) // e.g. "pages", which ssotrace doesn't use
		}
		if err != nil {
			return err
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return describe(err)
	}
	return nil
}

func decodeEntries(dec *json.Decoder, entries *[]Entry) error {
	if err := expectDelim(dec, '['); err != nil {
		return fmt.Errorf("entries: %w", err)
	}
	for i := 0; dec.More(); i++ {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			return fmt.Errorf("entry %d: %w", i, describe(err))
		}
		*entries = append(*entries, e)
	}
	if err := expectDelim(dec, ']'); err != nil {
		return fmt.Errorf("entries: %w", err)
	}
	return nil
}

func decodeField(dec *json.Decoder, name string, v any) error {
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", name, describe(err))
	}
	return nil
}

// skipValue discards the next JSON value. It buffers that one value, which
// is fine because the whole input is already size-bounded.
func skipValue(dec *json.Decoder) error {
	var discard json.RawMessage
	if err := dec.Decode(&discard); err != nil {
		return describe(err)
	}
	return nil
}

func readKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", describe(err)
	}
	key, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("expected an object key, found %s", describeToken(tok))
	}
	return key, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return describe(err)
	}
	if got, ok := tok.(json.Delim); !ok || got != want {
		// rune(): json.Delim is a fmt.Stringer, so %q on it would print "{"
		// in double quotes rather than '{'.
		return fmt.Errorf("expected %q, found %s", rune(want), describeToken(tok))
	}
	return nil
}

// describeToken names a JSON token's kind without revealing its content.
// String tokens come straight from the file and could be secrets.
func describeToken(tok json.Token) string {
	switch t := tok.(type) {
	case json.Delim:
		return fmt.Sprintf("%q", rune(t))
	case string:
		return "a string"
	case float64, json.Number:
		return "a number"
	case bool:
		return "a boolean"
	case nil:
		return "null"
	default:
		return "an unexpected token"
	}
}

// describe turns encoding/json errors into messages a person can act on,
// keeping the original error in the chain for errors.Is and errors.As.
func describe(err error) error {
	var syntax *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return fmt.Errorf("%w: the file ends early; it may be truncated (%w)", ErrNotHAR, err)
	case errors.As(err, &syntax):
		return fmt.Errorf("%w: malformed JSON at byte %d (%w)", ErrNotHAR, syntax.Offset, err)
	case errors.As(err, &typ):
		// typ.Value is a kind ("string", "number 1.5"), never a string's content.
		// The original message repeats the same facts, so it is not appended.
		return fmt.Errorf("field %q has the wrong type: got %s, want %s", typ.Field, typ.Value, typ.Type)
	default:
		return err
	}
}

// FormatBytes renders a byte count in binary units, e.g. "256.0 MiB".
func FormatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d bytes", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 3; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
