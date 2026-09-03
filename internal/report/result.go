// Package report renders a scan's findings, RBAC role model, and
// compliance scorecards into the tool's two output formats: findings.json
// (machine readable) and report.md (human readable, driven by a Go
// text/template — see templates/default.md.tpl).
package report

import (
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/compliance"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/rbac"
	"github.com/ivanhahanov/kubectl-audit/internal/thirdparty"
)

// ScopeNote explains one category of check this scan structurally couldn't
// run (or could only run incompletely) — surfaced once, prominently, in
// the report's Scope section, instead of relying on a reader to notice a
// dozen individually-worded NOT_APPLICABLE compliance rows saying similar
// things.
type ScopeNote struct {
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

// Scope is what this particular scan could and couldn't see, computed once
// from what was actually loaded/observed (see internal/cli's buildScope).
type Scope struct {
	OutOfScope []ScopeNote `json:"outOfScope,omitempty"`
	// Caveats are checks that DID run (unlike OutOfScope) but carry a
	// lower-confidence warning worth surfacing prominently once instead of
	// repeating in every affected finding — e.g. alpha/experimental check
	// families like istio.*.
	Caveats []ScopeNote `json:"caveats,omitempty"`
}

// SuppressedFinding is a finding an exclusion rule (see
// config.ExclusionRule) matched, kept in the report with its reason instead
// of silently vanishing. Excluded from Summary, the --fail-on gate, and CSV
// export — but still visible in the Markdown/JSON report.
type SuppressedFinding struct {
	Finding findings.Finding `json:"finding"`
	Reason  string           `json:"reason"`
}

// Result is everything a scan produced, ready to render.
type Result struct {
	GeneratedAt time.Time
	Target      string
	// ClusterVersion is the detected Kubernetes server version (e.g.
	// "v1.27.16"), empty for a static-manifest-only scan or if detection
	// failed. See internal/k8sversion.
	ClusterVersion string
	// ClusterEndpoint is the API server URL from the resolved kubeconfig
	// (rest.Config.Host, e.g. "https://10.0.5.2:6443" or a managed
	// cluster's DNS name) — not always a literal IP address, hence the
	// name, but the closest available "where is this cluster" signal.
	// Empty for a static-manifest-only scan.
	ClusterEndpoint string
	// Owner is a free-text "who's responsible for this report" field —
	// config output.owner / --owner, purely informational, never derived.
	// Empty (the default) omits it from the report header.
	Owner          string
	Scope          Scope
	PoliciesLoaded int
	Findings       []findings.Finding
	Suppressed     []SuppressedFinding
	RBACModel      []rbac.SubjectModel
	Frameworks     []compliance.Scorecard
	// ReportView selects how RenderMarkdown structures the Findings
	// section(s): "check" (default), "namespace", or "both". Empty is
	// treated as "check". See config.OutputConfig.ReportView.
	ReportView string
	// MultipleSources is true when this scan actually loaded resources
	// from more than one distinct place (e.g. several files in a
	// directory scan, or --mode both mixing static files with a live
	// cluster). Computed from the loaded resources themselves (see
	// internal/cli's runScan), not from findings' Source strings — native
	// analyzers (RBAC, PSS, NetworkPolicy, ...) stamp their findings with
	// the whole scan's target string rather than one input resource's
	// origin, which would make a naive per-finding comparison unreliable.
	// The template only prints each finding's "(source)" suffix when this
	// is true — with a single source it's always identical to the
	// report's own Target line already shown once at the top.
	MultipleSources bool
	// DetectedComponents lists every third-party operator/CNI this tool
	// knows about (see internal/thirdparty) that was actually observed in
	// this scan — CRD group presence and/or a known label match. Purely
	// informational: explains why third-party-CRD checks or built-in PSS
	// exceptions did or didn't produce anything, instead of leaving that
	// implicit.
	DetectedComponents []thirdparty.Detection
	// NamespaceGroupThreshold controls collapsing repeated Kind/Name
	// findings across namespaces in the Markdown report — see
	// config.OutputConfig.NamespaceGroupThreshold for the full rationale.
	// 0 (the zero value, so callers that don't set it get today's
	// behavior) disables collapsing.
	NamespaceGroupThreshold int
	// GroupByNamePattern extends NamespaceGroupThreshold's collapsing to
	// also match resources whose *name itself* is per-tenant-generated
	// (e.g. a UUID-suffixed Namespace name), not just an identical literal
	// name repeated across namespaces — see
	// config.OutputConfig.GroupByNamePattern.
	GroupByNamePattern bool
	// KnowledgeBase is an organization's own Title/Category/Remediation
	// overrides per PolicyID (see findings.KnowledgeBaseEntry) — the same
	// content triage.knowledgeBaseFile already provides for the triage TUI
	// and Jira ticket rendering, now also applied to the report so a
	// customized check reads the same everywhere. Nil (the zero value)
	// means no overrides — every check renders its own default content,
	// today's behavior.
	KnowledgeBase map[string]findings.KnowledgeBaseEntry
}

// Summary counts findings by severity. Suppressed findings aren't counted.
func (r Result) Summary() findings.Summary {
	return findings.Summarize(r.Findings)
}
