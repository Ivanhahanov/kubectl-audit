// Package report renders a scan's findings, RBAC role model, and CIS
// scorecard into the tool's two output formats: findings.json (machine
// readable) and report.md (human readable).
package report

import (
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/cis"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/rbac"
)

// Result is everything a scan produced, ready to render.
type Result struct {
	GeneratedAt    time.Time
	Target         string
	PoliciesLoaded int
	Findings       []findings.Finding
	RBACModel      []rbac.SubjectModel
	CIS            *cis.Scorecard
}

// Summary counts findings by severity.
func (r Result) Summary() findings.Summary {
	return findings.Summarize(r.Findings)
}
