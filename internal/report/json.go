package report

import (
	"encoding/json"
	"os"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/compliance"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/rbac"
)

type jsonOutput struct {
	GeneratedAt       time.Time                     `json:"generatedAt"`
	Target            string                        `json:"target"`
	ClusterVersion    string                        `json:"clusterVersion,omitempty"`
	Scope             Scope                         `json:"scope"`
	PoliciesLoaded    int                           `json:"policiesLoaded"`
	Summary           findings.Summary              `json:"summary"`
	Findings          []findings.Finding            `json:"findings"`
	RBACModel         []rbac.SubjectModel           `json:"rbacModel,omitempty"`
	Frameworks        []compliance.Scorecard        `json:"compliance,omitempty"`
	ComplianceSummary []compliance.FrameworkSummary `json:"complianceSummary,omitempty"`
}

// RenderJSON marshals a Result to indented JSON.
func RenderJSON(r Result) ([]byte, error) {
	out := jsonOutput{
		GeneratedAt:       r.GeneratedAt,
		Target:            r.Target,
		ClusterVersion:    r.ClusterVersion,
		Scope:             r.Scope,
		PoliciesLoaded:    r.PoliciesLoaded,
		Summary:           r.Summary(),
		Findings:          nonNil(r.Findings),
		RBACModel:         r.RBACModel,
		Frameworks:        r.Frameworks,
		ComplianceSummary: compliance.Summarize(r.Frameworks),
	}
	return json.MarshalIndent(out, "", "  ")
}

// WriteJSON renders and writes findings.json to path.
func WriteJSON(path string, r Result) error {
	data, err := RenderJSON(r)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func nonNil(f []findings.Finding) []findings.Finding {
	if f == nil {
		return []findings.Finding{}
	}
	return f
}
