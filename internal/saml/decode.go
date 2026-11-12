package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxInflated caps how large one DEFLATE payload may grow when inflated.
// A few hundred bytes of DEFLATE can expand to gigabytes (a "zip bomb"), so
// the cap applies to the output, not the input. Real AuthnRequests inflate
// to a few kilobytes.
const MaxInflated = 10 << 20

// ErrInflateLimit means a Redirect-binding payload inflated past MaxInflated.
var ErrInflateLimit = errors.New("inflated payload exceeds limit")

// DecodePOST decodes an HTTP-POST binding value: plain base64.
//
// Some IdPs wrap the base64 at 64 or 76 characters, so whitespace is removed
// first rather than treated as an error.
func DecodePOST(value string) ([]byte, error) {
	return decodeBase64(value)
}

// DecodeRedirect decodes an HTTP-Redirect binding value: base64, then raw
// DEFLATE (RFC 1951) with no zlib or gzip header.
//
// When inflating fails, the error names the common mistakes, a zlib or gzip
// header, or no compression at all, because those are real SP bugs that
// ssotrace should explain rather than just reject.
func DecodeRedirect(value string) ([]byte, error) {
	compressed, err := decodeBase64(value)
	if err != nil {
		return nil, err
	}
	// Read one byte past the limit: if it arrives, the payload is too big.
	r := io.LimitReader(flate.NewReader(bytes.NewReader(compressed)), MaxInflated+1)
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("inflate: %s", describeCompression(compressed))
	}
	if len(out) > MaxInflated {
		return nil, fmt.Errorf("inflate: %w (%d MiB)", ErrInflateLimit, MaxInflated>>20)
	}
	return out, nil
}

// describeCompression explains why raw DEFLATE could not read data, by
// looking at its first bytes. It never echoes the data itself.
func describeCompression(data []byte) string {
	switch {
	case len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b:
		return "payload is gzip, but the Redirect binding requires raw DEFLATE"
	case len(data) >= 2 && data[0] == 0x78 && (uint16(data[0])<<8|uint16(data[1]))%31 == 0:
		// A zlib header is 0x78 then a byte chosen so the pair divides by 31.
		return "payload has a zlib header, but the Redirect binding requires raw DEFLATE"
	case len(bytes.TrimSpace(data)) > 0 && bytes.TrimSpace(data)[0] == '<':
		return "payload is uncompressed XML, but the Redirect binding requires DEFLATE"
	default:
		return "payload is not valid DEFLATE data"
	}
}

func decodeBase64(value string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, value)
	if clean == "" {
		return nil, errors.New("base64: value is empty")
	}
	b, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		// Some senders drop the "=" padding.
		if b2, err2 := base64.RawStdEncoding.DecodeString(clean); err2 == nil {
			return b2, nil
		}
		var cie base64.CorruptInputError
		if errors.As(err, &cie) {
			return nil, fmt.Errorf("base64: invalid data at byte %d", int64(cie))
		}
		return nil, errors.New("base64: invalid data")
	}
	return b, nil
}
