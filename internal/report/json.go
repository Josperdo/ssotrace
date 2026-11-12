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
	Findings      []diagnose.Finding `json:"findings"`
	SAML          *flow.SAMLTrace    `json:"saml"`
}

// JSON writes findings and the SAML trace as one indented JSON document.
func JSON(w io.Writer, findings []diagnose.Finding, trace *flow.SAMLTrace) error {
	if findings == nil {
		// An empty list, not null, so consumers can always iterate.
		findings = []diagnose.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// The default escapes <, >, and & as < etc. for HTML safety; this
	// output is for terminals and scripts, and URLs read better unescaped.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(jsonReport{SchemaVersion: SchemaVersion, Findings: findings, SAML: trace}); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}
	return nil
}
