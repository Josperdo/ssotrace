package cli

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/Josperdo/ssotrace/internal/har"
)

// byteSize is a flag.Value for sizes like "512MiB". Binary units only:
// "MB" is rejected rather than guessed at, because 1 MB and 1 MiB differ
// and a size limit should mean exactly what the user typed.
type byteSize int64

var sizeUnits = []struct {
	suffix string
	mult   int64
}{
	// Longest suffixes first, so "MiB" is not mistaken for a bare "B".
	{"gib", 1 << 30},
	{"mib", 1 << 20},
	{"kib", 1 << 10},
	{"b", 1},
}

func (s *byteSize) String() string { return har.FormatBytes(int64(*s)) }

func (s *byteSize) Set(v string) error {
	n, err := parseByteSize(v)
	if err != nil {
		return err
	}
	*s = byteSize(n)
	return nil
}

func parseByteSize(v string) (int64, error) {
	lower := strings.ToLower(strings.TrimSpace(v))
	mult := int64(1)
	for _, u := range sizeUnits {
		if strings.HasSuffix(lower, u.suffix) {
			lower = strings.TrimSpace(strings.TrimSuffix(lower, u.suffix))
			mult = u.mult
			break
		}
	}
	n, err := strconv.ParseInt(lower, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid size %q (use a whole number with KiB, MiB, or GiB, e.g. 512MiB)", v)
	}
	if n > math.MaxInt64/mult {
		return 0, fmt.Errorf("invalid size %q: too large", v)
	}
	return n * mult, nil
}
