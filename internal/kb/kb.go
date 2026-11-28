package kb

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

//go:embed codes.json
var codesJSON []byte

// Entry explains one error code or message.
type Entry struct {
	Vendor string `json:"vendor"`
	// Exactly one of Code and Message is set. A code is a token such as
	// AADSTS50105; a message is a sentence the provider shows verbatim.
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Cause   string `json:"cause"`
	Fix     string `json:"fix"`
}

// Key is what identifies the entry in a capture: its code or message.
func (e Entry) Key() string {
	if e.Code != "" {
		return e.Code
	}
	return e.Message
}

// Base is the loaded knowledge base.
type Base struct {
	entries []Entry
	byKey   map[string]int
}

// Lookup returns the entry for a code or message, matched exactly.
func (b *Base) Lookup(key string) (Entry, bool) {
	if b == nil {
		return Entry{}, false
	}
	i, ok := b.byKey[key]
	if !ok {
		return Entry{}, false
	}
	return b.entries[i], true
}

// Codes returns the entries identified by a code, in file order.
func (b *Base) Codes() []Entry { return b.filter(func(e Entry) bool { return e.Code != "" }) }

// Messages returns the entries identified by a message, in file order.
func (b *Base) Messages() []Entry { return b.filter(func(e Entry) bool { return e.Message != "" }) }

func (b *Base) filter(keep func(Entry) bool) []Entry {
	if b == nil {
		return nil
	}
	var out []Entry
	for _, e := range b.entries {
		if keep(e) {
			out = append(out, e)
		}
	}
	return out
}

// Default is the knowledge base embedded in the binary. It is parsed once,
// on first use. The embedded file is checked by this package's tests, so a
// parse error here means a broken build; callers get an empty base rather
// than a crash.
var Default = sync.OnceValue(func() *Base {
	b, err := Parse(codesJSON)
	if err != nil {
		return &Base{}
	}
	return b
})

// Limits that keep entries short enough to read in a terminal finding.
const (
	maxText    = 400
	minMessage = 8
	maxMessage = 120
)

// codeRE is the shape of a code: letters, digits, and underscores, so it
// can be matched on word boundaries.
var codeRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{2,39}$`)

// Parse reads and validates a knowledge base file. Unknown fields are
// errors, so a typo in a field name cannot silently drop a fix.
func Parse(data []byte) (*Base, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc struct {
		Entries []Entry `json:"entries"`
	}
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("knowledge base: %w", err)
	}
	if len(doc.Entries) == 0 {
		return nil, errors.New("knowledge base: no entries")
	}
	b := &Base{entries: doc.Entries, byKey: map[string]int{}}
	for i, e := range doc.Entries {
		if err := e.validate(); err != nil {
			return nil, fmt.Errorf("knowledge base: entry %d (%s): %w", i+1, e.Key(), err)
		}
		if _, dup := b.byKey[e.Key()]; dup {
			return nil, fmt.Errorf("knowledge base: entry %d: %q is listed twice", i+1, e.Key())
		}
		b.byKey[e.Key()] = i
	}
	return b, nil
}

func (e Entry) validate() error {
	switch {
	case strings.TrimSpace(e.Vendor) == "":
		return errors.New("vendor is empty")
	case (e.Code == "") == (e.Message == ""):
		return errors.New("set exactly one of code and message")
	case e.Code != "" && !codeRE.MatchString(e.Code):
		return errors.New("code must be 3-40 letters, digits, or underscores, starting with a letter")
	case e.Message != "" && (len(e.Message) < minMessage || len(e.Message) > maxMessage):
		return fmt.Errorf("message must be %d-%d characters", minMessage, maxMessage)
	case e.Message != "" && strings.ContainsAny(e.Message, "<>&\"'"):
		// Pages HTML-escape these characters, so a message containing one
		// would never match the page's source.
		return errors.New(`message must not contain < > & " or '`)
	}
	for name, text := range map[string]string{"cause": e.Cause, "fix": e.Fix} {
		switch {
		case strings.TrimSpace(text) == "":
			return fmt.Errorf("%s is empty", name)
		case len(text) > maxText:
			return fmt.Errorf("%s is over %d characters", name, maxText)
		case !strings.HasSuffix(text, "."):
			return fmt.Errorf("%s must be a sentence ending in a period", name)
		}
	}
	return nil
}
