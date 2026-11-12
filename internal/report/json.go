package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Josperdo/ssotrace/internal/diagnose"
	"github.com/Josperdo/ssotrace/internal/flow"
)

// SchemaVersion is the version of the JSON output shape. Scripts depend on
// it: bump it only for a change that would break an existing consumer
// (removing or renaming a field), not for added fields.
const SchemaVersion = 1

// jsonReport is the top-level JSON document.
type jsonReport struct {
	SchemaVersion int                `json:"schema_version"`
	Version       string             `json:"ssotrace_version,omitempty"`
	File          string             `json:"file,omitempty"`
	Summary       Counts             `json:"summary"`
	Findings      []diagnose.Finding `json:"findings"`
	SAML          *flow.SAMLTrace    `json:"saml"`
}

// JSON writes the report as one indented JSON document. Every finding is
// included, passes too, so scripts can tell "checked and fine" from "not
// checked". Strings are escaped by encoding/json, so control characters
// from the HAR cannot reach a terminal that later prints the JSON raw.
func JSON(w io.Writer, r *Report) error {
	findings := r.Findings
	if findings == nil {
		// An empty list, not null, so consumers can always iterate.
		findings = []diagnose.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// The default escapes <, >, and & as < etc. for HTML safety; this
	// output is for terminals and scripts, and URLs read better unescaped.
	enc.SetEscapeHTML(false)
	doc := jsonReport{
		SchemaVersion: SchemaVersion,
		Version:       r.Version,
		File:          r.File,
		Summary:       r.counts(),
		Findings:      findings,
		SAML:          r.SAML,
	}
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}
	return nil
}
