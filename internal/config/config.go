// Package config defines the audit.yaml schema and loads/merges it with CLI overrides.
package config

import (
	"fmt"
	"os"

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
	Mode          TargetMode `json:"mode,omitempty"`
	Context       string     `json:"context,omitempty"`
	Kubeconfig    string     `json:"kubeconfig,omitempty"`
	Namespaces    []string   `json:"namespaces,omitempty"`
	AllNamespaces bool       `json:"allNamespaces,omitempty"`
	Paths         []string   `json:"paths,omitempty"`
	IncludeKinds  []string   `json:"includeKinds,omitempty"`
	ExcludeKinds  []string   `json:"excludeKinds,omitempty"`

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
	FailOn   string `json:"failOn,omitempty"`
}

// CISConfig toggles CIS Benchmark scorecard generation.
type CISConfig struct {
	Enabled bool   `json:"enabled"`
	Version string `json:"version,omitempty"`
}

// AuditConfig is the root audit.yaml schema.
type AuditConfig struct {
	Target   TargetConfig   `json:"target,omitempty"`
	Policies PoliciesConfig `json:"policies,omitempty"`
	Output   OutputConfig   `json:"output,omitempty"`
	CIS      CISConfig      `json:"cis,omitempty"`
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
			JSON:     "findings.json",
			Markdown: "report.md",
			FailOn:   "high",
		},
		CIS: CISConfig{
			Enabled: true,
			Version: "1.8",
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
	return cfg, nil
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
