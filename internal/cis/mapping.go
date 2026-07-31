// Package cis maps audit findings onto CIS Kubernetes Benchmark controls
// and builds a compliance scorecard, including explicit "not applicable"
// rows for controls that require node/file access this tool can't reach.
package cis

import (
	"fmt"

	"sigs.k8s.io/yaml"

	cismappings "github.com/ivanhahanov/kubectl-audit/cis-mappings"
)

// Control is one row of the CIS control table.
type Control struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Section     string   `json:"section"`
	Applicable  bool     `json:"applicable"`
	Implemented *bool    `json:"implemented,omitempty"`
	PolicyIDs   []string `json:"policyIds,omitempty"`
	// NativeCheckIDs are IDs from Go-native analyzers (not CEL policies)
	// that require cross-object reasoning a single-object VAP expression
	// can't do, e.g. "rbac-analyzer.*" and "netpol-analyzer.*".
	NativeCheckIDs []string `json:"nativeCheckIds,omitempty"`
	NAReason       string   `json:"naReason,omitempty"`
	Note           string   `json:"note,omitempty"`
}

// IsImplemented reports whether this audit tool has a check for the
// control (defaults to true when unset).
func (c Control) IsImplemented() bool {
	if c.Implemented == nil {
		return true
	}
	return *c.Implemented
}

// CheckIDs returns every policy/native-check ID that maps to this control.
func (c Control) CheckIDs() []string {
	out := make([]string, 0, len(c.PolicyIDs)+len(c.NativeCheckIDs))
	out = append(out, c.PolicyIDs...)
	out = append(out, c.NativeCheckIDs...)
	return out
}

// Mapping is the full CIS control table for a benchmark version.
type Mapping struct {
	Version  string    `json:"version"`
	Controls []Control `json:"controls"`
}

// LoadMapping reads the embedded CIS Kubernetes Benchmark control table.
func LoadMapping() (*Mapping, error) {
	data, err := cismappings.FS.ReadFile("mapping.yaml")
	if err != nil {
		return nil, fmt.Errorf("reading embedded CIS mapping: %w", err)
	}
	var m Mapping
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing embedded CIS mapping: %w", err)
	}
	return &m, nil
}
