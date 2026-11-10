package diagnose

import (
	"encoding/json"
	"slices"
	"testing"
)

// stubRule is a minimal Rule for registry tests.
type stubRule struct{ id string }

func (s stubRule) ID() string              { return s.id }
func (s stubRule) Check(Context) []Finding { return nil }

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{Pass, "pass"},
		{Info, "info"},
		{Warn, "warn"},
		{Fail, "fail"},
		{Severity(99), "severity(99)"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", int(tt.sev), got, tt.want)
		}
	}
}

func TestSeverityJSON(t *testing.T) {
	tests := []struct {
		sev  Severity
		json string
	}{
		{Pass, `"pass"`},
		{Info, `"info"`},
		{Warn, `"warn"`},
		{Fail, `"fail"`},
	}
	for _, tt := range tests {
		t.Run(tt.sev.String(), func(t *testing.T) {
			got, err := json.Marshal(tt.sev)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(got) != tt.json {
				t.Errorf("Marshal = %s, want %s", got, tt.json)
			}

			var back Severity
			if err := json.Unmarshal(got, &back); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if back != tt.sev {
				t.Errorf("round trip = %v, want %v", back, tt.sev)
			}
		})
	}
}

func TestSeverityJSONErrors(t *testing.T) {
	if _, err := json.Marshal(Severity(42)); err == nil {
		t.Error("Marshal(Severity(42)) succeeded, want error")
	}
	var s Severity
	if err := json.Unmarshal([]byte(`"catastrophic"`), &s); err == nil {
		t.Error(`Unmarshal("catastrophic") succeeded, want error`)
	}
	if err := json.Unmarshal([]byte(`3`), &s); err == nil {
		t.Error("Unmarshal(3) succeeded, want error (names only)")
	}
}

func TestRegistry(t *testing.T) {
	tests := []struct {
		name    string
		ids     []string
		wantErr bool     // whether the last Register call should fail
		wantIDs []string // IDs returned by Rules(), in order
	}{
		{
			name:    "empty",
			ids:     nil,
			wantIDs: []string{},
		},
		{
			name:    "sorted by ID regardless of registration order",
			ids:     []string{"SAML002", "HAR001", "OIDC001", "SAML001"},
			wantIDs: []string{"HAR001", "OIDC001", "SAML001", "SAML002"},
		},
		{
			name:    "duplicate ID rejected",
			ids:     []string{"SAML001", "SAML001"},
			wantErr: true,
			wantIDs: []string{"SAML001"},
		},
		{
			name:    "empty ID rejected",
			ids:     []string{""},
			wantErr: true,
			wantIDs: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := NewRegistry()
			var lastErr error
			for _, id := range tt.ids {
				lastErr = reg.Register(stubRule{id: id})
			}
			if (lastErr != nil) != tt.wantErr {
				t.Errorf("last Register error = %v, wantErr %v", lastErr, tt.wantErr)
			}

			got := []string{}
			for _, r := range reg.Rules() {
				got = append(got, r.ID())
			}
			if !slices.Equal(got, tt.wantIDs) {
				t.Errorf("Rules() IDs = %v, want %v", got, tt.wantIDs)
			}
		})
	}
}

func TestHasFailures(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		want     bool
	}{
		{"nil", nil, false},
		{"only pass/info/warn", []Finding{{Severity: Pass}, {Severity: Info}, {Severity: Warn}}, false},
		{"one fail", []Finding{{Severity: Warn}, {Severity: Fail}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasFailures(tt.findings); got != tt.want {
				t.Errorf("HasFailures = %v, want %v", got, tt.want)
			}
		})
	}
}
