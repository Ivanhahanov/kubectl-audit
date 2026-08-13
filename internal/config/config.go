// Package config defines the audit.yaml schema and loads/merges it with CLI overrides.
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"

	"sigs.k8s.io/yaml"
)

// TargetMode selects where manifests are loaded from.
type TargetMode string

const (
	ModeCluster TargetMode = "cluster"
	ModeStatic  TargetMode = "static"
	ModeBoth    TargetMode = "both"
)

// TargetConfig describes where audited resources come from.
type TargetConfig struct {
	Mode       TargetMode `json:"mode,omitempty"`
	Context    string     `json:"context,omitempty"`
	Kubeconfig string     `json:"kubeconfig,omitempty"`
	// ClusterName overrides the report's Target field and every finding's
	// Source for a cluster-mode scan, in place of the raw kube-context name
	// (which defaults to "current-context" when --context isn't set, or can
	// be an unreadable cloud-provider ARN/UUID). Purely cosmetic — doesn't
	// affect which cluster is actually scanned.
	ClusterName   string   `json:"clusterName,omitempty"`
	Namespaces    []string `json:"namespaces,omitempty"`
	AllNamespaces bool     `json:"allNamespaces,omitempty"`
	Paths         []string `json:"paths,omitempty"`
	IncludeKinds  []string `json:"includeKinds,omitempty"`
	ExcludeKinds  []string `json:"excludeKinds,omitempty"`

	// ExcludeNamespaces are skipped entirely, regardless of mode. Defaults
	// to the platform-managed namespaces (see config.Default), since their
	// workloads/RBAC objects are Kubernetes/CNI/CSI internals that dominate
	// reports without being actionable. Ignored when Namespaces (an
	// explicit allowlist) is set.
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`

	// IncludeSystemRBAC, when true, keeps Role/ClusterRole/*Binding objects
	// named with the reserved "system:" prefix (Kubernetes' own built-in
	// RBAC) in scope. They're excluded by default: they're cluster-managed
	// and not something an operator can remediate.
	IncludeSystemRBAC bool `json:"includeSystemRBAC,omitempty"`

	// CheckUpdates, when true, makes a live HTTPS request to endoflife.date
	// to check the detected cluster version for available patch releases
	// and real EOL/support status — the only network call this tool ever
	// makes beyond the target cluster itself. Off by default so the tool
	// stays fully usable in air-gapped/restricted-network environments;
	// see internal/k8supdates.
	CheckUpdates bool `json:"checkUpdates,omitempty"`
}

// PoliciesConfig controls which policies are loaded.
type PoliciesConfig struct {
	Dirs    []string `json:"dirs,omitempty"`
	Disable []string `json:"disable,omitempty"`
	Builtin *bool    `json:"builtin,omitempty"`
}

// BuiltinEnabled reports whether bundled policies should load (default true).
func (p PoliciesConfig) BuiltinEnabled() bool {
	if p.Builtin == nil {
		return true
	}
	return *p.Builtin
}

// IsDisabled reports whether a policy ID was explicitly disabled.
func (p PoliciesConfig) IsDisabled(id string) bool {
	for _, d := range p.Disable {
		if d == id {
			return true
		}
	}
	return false
}

// OutputConfig controls report output paths and the CI failure threshold.
type OutputConfig struct {
	JSON     string `json:"json,omitempty"`
	Markdown string `json:"markdown,omitempty"`
	// CSV is a path to write findings as CSV, one row per finding — for
	// loading into a spreadsheet to sort/filter/assign owners. Empty (the
	// default) skips CSV output entirely; unlike JSON/Markdown there's no
	// default filename, since most invocations don't want it.
	CSV    string `json:"csv,omitempty"`
	FailOn string `json:"failOn,omitempty"`
	// Template is a path to a custom report.md.tpl (Go text/template). Empty
	// uses the embedded default template.
	Template string `json:"template,omitempty"`
	// ReportView selects how the Markdown report's Findings section(s) are
	// structured: "check" (default) groups findings by check/policy ID —
	// each check's title/remediation shown once, followed by the resources
	// it fired on; "namespace" groups by namespace/resource instead, full
	// detail per finding; "both" renders the check-grouped view plus a
	// compact by-namespace index. On a large cluster "both" roughly doubles
	// the number of finding lines in the report (every finding listed once
	// per view) — "check" (or "namespace" for a per-team handoff) avoids
	// that duplication.
	ReportView string `json:"reportView,omitempty"`
}

// ValidReportViews are the accepted values for ReportView.
var ValidReportViews = map[string]bool{"check": true, "namespace": true, "both": true}

// ComplianceConfig selects which requirement frameworks to score against
// (e.g. "cis", "fstec", "nsa" — see compliance-mappings/).
type ComplianceConfig struct {
	Frameworks []string `json:"frameworks,omitempty"`
}

// ExclusionMatch selects which resources an ExclusionRule applies to. At
// least one field must be set (an entirely empty Match would silently
// suppress every finding it's paired with — rejected at load time instead).
// All set fields must match (AND) for a resource to match this rule.
type ExclusionMatch struct {
	// Kind is an exact match against the finding's resource Kind (e.g.
	// "Deployment", "ServiceAccount", "Group" — the same Kind RBAC
	// findings use for non-object subjects like system:masters).
	Kind string `json:"kind,omitempty"`
	// Namespace is an exact match. Empty matches cluster-scoped resources
	// too — pair with Kind/Name/Labels to avoid over-matching.
	Namespace string `json:"namespace,omitempty"`
	// Name is matched via path.Match glob syntax (e.g. "legacy-*"), so a
	// plain literal name still works as an exact match.
	Name string `json:"name,omitempty"`
	// Labels must all be present with equal values on the source object.
	// Only matches resources this tool actually loaded from the API/
	// manifests (has real labels to check) — RBAC findings whose Resource
	// is a Group/User subject (not a loaded object) never match a Labels
	// rule.
	Labels map[string]string `json:"labels,omitempty"`
}

// ExclusionRule suppresses matching findings from a scan's pass/fail
// output. Suppressed findings are never silently dropped: they're counted
// and listed with Reason in the Markdown/JSON report (see report.Result),
// and excluded from the --fail-on gate and CSV export.
type ExclusionRule struct {
	// PolicyIDs restricts this rule to specific checks; empty or ["*"]
	// applies it to every check.
	PolicyIDs []string       `json:"policyIds,omitempty"`
	Match     ExclusionMatch `json:"match"`
	// Reason is shown in the report next to every finding this rule
	// suppresses — required, so a suppression always carries a paper
	// trail instead of becoming an unexplained gap.
	Reason string `json:"reason"`
}

// AuditConfig is the root audit.yaml schema.
type AuditConfig struct {
	Target     TargetConfig     `json:"target,omitempty"`
	Policies   PoliciesConfig   `json:"policies,omitempty"`
	Output     OutputConfig     `json:"output,omitempty"`
	Compliance ComplianceConfig `json:"compliance,omitempty"`
	Exclusions []ExclusionRule  `json:"exclusions,omitempty"`
}

// Default returns an AuditConfig with sane production defaults.
func Default() *AuditConfig {
	return &AuditConfig{
		Target: TargetConfig{
			Mode:          ModeBoth,
			AllNamespaces: true,
			// Platform-managed namespaces present on virtually every
			// cluster; see loader.DefaultExcludedNamespaces for why these
			// are excluded by default. Override with an explicit
			// excludeNamespaces (possibly []) or a -n allowlist.
			ExcludeNamespaces: []string{"kube-system", "kube-public", "kube-node-lease"},
		},
		Policies: PoliciesConfig{
			Builtin: boolPtr(true),
		},
		Output: OutputConfig{
			JSON:       "findings.json",
			Markdown:   "report.md",
			FailOn:     "high",
			ReportView: "check",
		},
		Compliance: ComplianceConfig{
			Frameworks: []string{"cis"},
		},
	}
}

func boolPtr(b bool) *bool { return &b }

// Load reads audit.yaml from path (if non-empty) and merges it onto the
// defaults. If path is empty, defaults are returned unchanged (no file is
// required to run the tool). If path is non-empty and unreadable, an error
// is returned.
func Load(path string) (*AuditConfig, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if err := validateExclusions(cfg.Exclusions); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return cfg, nil
}

// validateExclusions rejects rules that would silently suppress more than
// intended: a Reason is mandatory (so every suppression carries a paper
// trail), and Match must set at least one field (an empty Match would
// suppress every finding for every resource).
func validateExclusions(rules []ExclusionRule) error {
	for i, r := range rules {
		if strings.TrimSpace(r.Reason) == "" {
			return fmt.Errorf("exclusions[%d]: reason is required", i)
		}
		m := r.Match
		if m.Kind == "" && m.Namespace == "" && m.Name == "" && len(m.Labels) == 0 {
			return fmt.Errorf("exclusions[%d]: match must set at least one of kind, namespace, name, or labels", i)
		}
	}
	return nil
}

// FailOnSeverity resolves the configured failOn threshold, treating
// "none"/"" as "never fail".
func (c *AuditConfig) FailOnSeverity() (findings.Severity, bool) {
	switch normalize(c.Output.FailOn) {
	case "", "none":
		return "", false
	default:
		return findings.ParseSeverity(c.Output.FailOn), true
	}
}

func normalize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}
