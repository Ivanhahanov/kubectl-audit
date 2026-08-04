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
}

// Result is everything a scan produced, ready to render.
type Result struct {
	GeneratedAt time.Time
	Target      string
	// ClusterVersion is the detected Kubernetes server version (e.g.
	// "v1.27.16"), empty for a static-manifest-only scan or if detection
	// failed. See internal/k8sversion.
	ClusterVersion string
	Scope          Scope
	PoliciesLoaded int
	Findings       []findings.Finding
	RBACModel      []rbac.SubjectModel
	Frameworks     []compliance.Scorecard
}

// Summary counts findings by severity.
func (r Result) Summary() findings.Summary {
	return findings.Summarize(r.Findings)
}
