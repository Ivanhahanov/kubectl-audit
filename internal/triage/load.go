package triage

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/report"
)

// findingsFile is the minimal shape of a scan's findings.json this package
// actually needs — the top-level "findings" and "suppressed" arrays.
// internal/report's own jsonOutput type is unexported and write-only
// (report.WriteJSON has no counterpart reader), so this is deliberately not
// shared with it; unknown fields (summary, compliance, ...) are ignored by
// encoding/json, so this stays forward-compatible with whatever else that
// document contains.
type findingsFile struct {
	Target     string                     `json:"target"`
	Findings   []findings.Finding         `json:"findings"`
	Suppressed []report.SuppressedFinding `json:"suppressed"`
}

// LoadFindings reads a findings.json file (as written by `kubectl audit
// scan --output-json`) and returns the scan's target label (e.g.
// "cluster:my-context" or "static:./manifests" — report.Result.Target,
// unchanged), its active findings, and its suppressed findings (each with
// the exclusion rule's Reason — see report.SuppressedFinding). Findings
// and suppressed findings share the same findings.Finding.ID scheme, so
// triage state (keyed by that ID) joins to either uniformly.
func LoadFindings(path string) (target string, all []findings.Finding, suppressed []report.SuppressedFinding, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var ff findingsFile
	if err := json.Unmarshal(data, &ff); err != nil {
		return "", nil, nil, fmt.Errorf("parsing %s as findings JSON: %w", path, err)
	}
	return ff.Target, ff.Findings, ff.Suppressed, nil
}
