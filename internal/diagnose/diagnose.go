// Package diagnose defines the rule engine contracts: severities, findings,
// the Rule interface, and the registry that holds rules.
package diagnose

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Josperdo/ssotrace/internal/har"
)

// Severity ranks how bad a finding is. The zero value is Pass so that an
// uninitialized Finding never claims to be a failure by accident.
type Severity int

// Severities in increasing order of seriousness. Order matters: renderers
// sort by it and HasFailures compares against Fail.
const (
	Pass Severity = iota
	Info
	Warn
	Fail
)

var severityNames = [...]string{
	Pass: "pass",
	Info: "info",
	Warn: "warn",
	Fail: "fail",
}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// MarshalJSON encodes a Severity as its lowercase name. JSON consumers get a
// readable, stable value instead of an integer tied to declaration order.
func (s Severity) MarshalJSON() ([]byte, error) {
	if s < 0 || int(s) >= len(severityNames) {
		return nil, fmt.Errorf("marshal severity: unknown value %d", int(s))
	}
	return json.Marshal(s.String())
}

// UnmarshalJSON decodes the lowercase name produced by MarshalJSON.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return fmt.Errorf("unmarshal severity: %w", err)
	}
	for i, n := range severityNames {
		if n == name {
			*s = Severity(i)
			return nil
		}
	}
	return fmt.Errorf("unmarshal severity: unknown name %q", name)
}

// Evidence is one labeled fact that supports a finding.
type Evidence struct {
	Label string `json:"label"` // e.g. "Assertion audience"
	Value string `json:"value"` // already safe to display (secrets previewed, never raw)
}

// Finding is the result of one rule check.
type Finding struct {
	RuleID   string     `json:"rule_id"` // e.g. "SAML002"
	Severity Severity   `json:"severity"`
	Title    string     `json:"title"`
	Detail   string     `json:"detail"`
	Evidence []Evidence `json:"evidence,omitempty"`
	Fix      string     `json:"fix,omitempty"`
}

// Context is everything a rule may look at.
//
// Rules read only from Context, never from files, the network, or the
// system clock: any reference time must come from here (or from HAR
// timestamps), never from time.Now(). That keeps a diagnosis a pure
// function of its input, so tests are deterministic.
type Context struct {
	// HAR is the loaded capture. Rules must tolerate nil and report nothing.
	HAR *har.HAR
}

// Rule is one diagnostic check. ID must be stable and never reused.
type Rule interface {
	ID() string
	Check(ctx Context) []Finding
}

// Registry holds the set of rules to run.
type Registry struct {
	rules map[string]Rule
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{rules: make(map[string]Rule)}
}

// Register adds r. It returns an error if r has an empty ID or an ID that is
// already registered: two rules sharing an ID would make findings ambiguous.
func (r *Registry) Register(rule Rule) error {
	id := rule.ID()
	if id == "" {
		return fmt.Errorf("register rule: empty ID")
	}
	if _, exists := r.rules[id]; exists {
		return fmt.Errorf("register rule %s: duplicate ID", id)
	}
	r.rules[id] = rule
	return nil
}

// Rules returns the registered rules sorted by ID. Map iteration order is
// random in Go, so sorting keeps output and tests deterministic.
func (r *Registry) Rules() []Rule {
	out := make([]Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// DefaultRules returns a registry holding every built-in rule.
func DefaultRules() (*Registry, error) {
	reg := NewRegistry()
	for _, r := range []Rule{
		noSSOTraffic{},
		missingRequestBodies{},
	} {
		if err := reg.Register(r); err != nil {
			return nil, fmt.Errorf("default rules: %w", err)
		}
	}
	return reg, nil
}

// Run checks ctx against every rule in reg, in rule ID order, and returns
// all findings.
func Run(ctx Context, reg *Registry) []Finding {
	var findings []Finding
	for _, r := range reg.Rules() {
		findings = append(findings, r.Check(ctx)...)
	}
	return findings
}

// HasFailures reports whether any finding has Fail severity. The CLI uses it
// to choose exit code 1.
func HasFailures(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == Fail {
			return true
		}
	}
	return false
}
