package kb

import (
	"strings"
	"testing"
)

// TestEmbeddedFileIsValid guards the shipped data: a broken codes.json
// would otherwise fail silently at run time, as an empty knowledge base.
func TestEmbeddedFileIsValid(t *testing.T) {
	b, err := Parse(codesJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Codes()) == 0 || len(b.Messages()) == 0 {
		t.Fatalf("codes = %d, messages = %d; want both", len(b.Codes()), len(b.Messages()))
	}
	if got := len(Default().entries); got != len(b.entries) {
		t.Errorf("Default has %d entries, want %d", got, len(b.entries))
	}
}

func TestLookup(t *testing.T) {
	b := Default()
	e, ok := b.Lookup("AADSTS50105")
	if !ok || e.Vendor != "Microsoft Entra ID" || !strings.Contains(e.Cause, "not assigned") {
		t.Errorf("Lookup(AADSTS50105) = %+v, %v", e, ok)
	}
	if e, ok := b.Lookup("Client not found."); !ok || e.Vendor != "Keycloak" {
		t.Errorf("Lookup(message) = %+v, %v", e, ok)
	}
	for _, miss := range []string{"AADSTS00000", "aadsts50105", ""} {
		if _, ok := b.Lookup(miss); ok {
			t.Errorf("Lookup(%q) found an entry", miss)
		}
	}
	var nilBase *Base
	if _, ok := nilBase.Lookup("AADSTS50105"); ok || nilBase.Codes() != nil {
		t.Error("nil Base is not empty")
	}
}

func TestParseRejects(t *testing.T) {
	entry := func(fields string) string { return `{"entries":[{` + fields + `}]}` }
	const ok = `"vendor":"V","cause":"Why.","fix":"Do this."`
	tests := []struct {
		name, doc, wantErr string
	}{
		{"unknown field", entry(ok + `,"code":"ABC123","fixx":"typo."`), "unknown field"},
		{"no entries", `{"entries":[]}`, "no entries"},
		{"not JSON", `nope`, "knowledge base"},
		{"neither code nor message", entry(ok), "exactly one"},
		{"both code and message", entry(ok + `,"code":"ABC123","message":"Some message."`), "exactly one"},
		{"code with spaces", entry(ok + `,"code":"AB C123"`), "letters, digits"},
		{"message too short", entry(ok + `,"message":"Bad."`), "characters"},
		{"message with a quote", entry(ok + `,"message":"Don't do that."`), "must not contain"},
		{"no vendor", entry(`"vendor":" ","code":"ABC123","cause":"Why.","fix":"Do this."`), "vendor"},
		{"cause not a sentence", entry(`"vendor":"V","code":"ABC123","cause":"why","fix":"Do this."`), "period"},
		{"fix too long", entry(`"vendor":"V","code":"ABC123","cause":"Why.","fix":"` + strings.Repeat("x", maxText) + `."`), "over"},
		{
			"duplicate", `{"entries":[{"vendor":"V","code":"ABC123","cause":"Why.","fix":"Do."},{"vendor":"W","code":"ABC123","cause":"Why.","fix":"Do."}]}`,
			"twice",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.doc))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
