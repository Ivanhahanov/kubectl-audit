// Package compliance maps audit findings onto controls from one or more
// external requirement frameworks (CIS Kubernetes Benchmark, FSTEC, NSA/CISA
// Kubernetes Hardening Guidance, ...) and builds a scorecard per framework,
// including explicit "not applicable"/"not implemented" rows for controls
// this tool structurally can't (or doesn't yet) evaluate.
package compliance

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"

	compliancemappings "github.com/ivanhahanov/kubectl-audit/compliance-mappings"
)

// Control is one row of a framework's control table.
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
	// CrossRefs points at the corresponding control ID(s) in other loaded
	// frameworks, keyed by framework ID (e.g. {"cis": ["5.2.4"]} on an
	// FSTEC control). Purely informational — rendered as a cross-reference
	// column, not consumed by scorecard building.
	CrossRefs map[string][]string `json:"crossRefs,omitempty"`
	NAReason  string              `json:"naReason,omitempty"`
	Note      string              `json:"note,omitempty"`
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

// Mapping is one framework's full control table.
type Mapping struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Version  string    `json:"version"`
	Controls []Control `json:"controls"`
}

// LoadMapping reads one framework control table, identified either by its
// embedded ID (filename without the .yaml extension, e.g. "cis", "fstec",
// "nsa") or, for a private/custom framework kept outside this repo, a
// filesystem path to a YAML file in the same shape (see
// compliance-mappings/*.yaml for the schema, or docs/custom-checks.md for a
// worked example). A path is any value containing a "/" or "\" or ending in
// ".yaml"/".yml"; anything else is looked up among the embedded frameworks.
//
// This is how org-specific requirements are meant to be scored without
// touching this (open-source) repo at all: write your own
// policies/*.yaml (--policy-dir) and your own compliance-mapping.yaml
// (--frameworks /path/to/it.yaml) referencing your own control IDs, and
// they flow through the exact same BuildScorecard/report pipeline as
// cis/fstec/nsa.
func LoadMapping(idOrPath string) (*Mapping, error) {
	data, isCustom, err := readMappingSource(idOrPath)
	if err != nil {
		return nil, err
	}
	var m Mapping
	if err := yaml.Unmarshal(data, &m); err != nil {
		kind := "embedded"
		if isCustom {
			kind = "custom"
		}
		return nil, fmt.Errorf("parsing %s compliance mapping %s: %w", kind, idOrPath, err)
	}
	if m.ID == "" {
		if isCustom {
			base := filepath.Base(idOrPath)
			m.ID = strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml")
		} else {
			m.ID = idOrPath
		}
	}
	return &m, nil
}

func isMappingPath(s string) bool {
	return strings.ContainsAny(s, "/\\") || strings.HasSuffix(s, ".yaml") || strings.HasSuffix(s, ".yml")
}

func readMappingSource(idOrPath string) (data []byte, isCustom bool, err error) {
	if isMappingPath(idOrPath) {
		data, err := os.ReadFile(idOrPath)
		if err != nil {
			return nil, true, fmt.Errorf("reading custom compliance mapping %s: %w", idOrPath, err)
		}
		return data, true, nil
	}
	data, err = compliancemappings.FS.ReadFile(idOrPath + ".yaml")
	if err != nil {
		return nil, false, fmt.Errorf("unknown compliance framework %q (not one of %s, and not a file path — a custom mapping's path must contain \"/\" or end in \".yaml\"/\".yml\")", idOrPath, strings.Join(mustAvailableFrameworks(), ", "))
	}
	return data, false, nil
}

// mustAvailableFrameworks is AvailableFrameworks with errors swallowed, for
// use inside an error message where a second failure shouldn't mask the
// first.
func mustAvailableFrameworks() []string {
	out, err := AvailableFrameworks()
	if err != nil {
		return nil
	}
	return out
}

// OverrideUnobserved returns a copy of the mapping where every control
// whose check IDs (policyIds and/or nativeCheckIds — see Control.CheckIDs)
// are all prefixed "<prefix><component>." for some component not present
// (or false) in observed is forced to NOT_APPLICABLE, with an explanatory
// NAReason, instead of computing as a false PASS.
//
// This exists for indirect/best-effort analyzers like internal/controlplane:
// their checks only run against control-plane components actually found as
// Pods in this scan (self-hosted/kubeadm-style clusters). On a managed
// control plane (EKS/GKE/AKS, ...) those Pods aren't visible via the API at
// all, so no findings are ever produced for them — which, left alone, would
// make BuildScorecard report "no matching findings" as PASS. Mappings that
// don't reference the given prefix are returned unchanged.
func OverrideUnobserved(m *Mapping, prefix string, observed map[string]bool) *Mapping {
	out := *m
	out.Controls = make([]Control, len(m.Controls))
	for i, c := range m.Controls {
		out.Controls[i] = c
		if comp, ok := unobservedComponent(c.CheckIDs(), prefix, observed); ok {
			out.Controls[i].Applicable = false
			out.Controls[i].Implemented = nil
			out.Controls[i].NAReason = fmt.Sprintf(
				"%q was not observed in this scan — e.g. a control-plane component's static Pod not visible via the Kubernetes API (a managed control plane such as EKS/GKE/AKS, or insufficient RBAC to list kube-system Pods), or a static-manifest-only scan with no live cluster to check at all.",
				comp)
		}
	}
	return &out
}

// unobservedComponent reports the component name if every one of ids
// belongs to "<prefix><component>." and that component is missing/false in
// observed. A control with no matching native check IDs, or one that mixes
// IDs from more than one component, is left alone.
func unobservedComponent(ids []string, prefix string, observed map[string]bool) (string, bool) {
	if len(ids) == 0 {
		return "", false
	}
	var component string
	for _, id := range ids {
		rest := strings.TrimPrefix(id, prefix)
		if rest == id {
			return "", false // doesn't have this prefix at all
		}
		parts := strings.SplitN(rest, ".", 2)
		if len(parts) != 2 {
			return "", false
		}
		if component == "" {
			component = parts[0]
		} else if component != parts[0] {
			return "", false // mixed components, don't guess
		}
	}
	if observed[component] {
		return "", false
	}
	return component, true
}

// AvailableFrameworks lists every embedded framework ID.
func AvailableFrameworks() ([]string, error) {
	entries, err := fs.ReadDir(compliancemappings.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("listing embedded compliance mappings: %w", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".yaml"))
	}
	return out, nil
}
