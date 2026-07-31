package report

import (
	"encoding/json"
	"os"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/cis"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/rbac"
)

type jsonOutput struct {
	GeneratedAt    time.Time           `json:"generatedAt"`
	Target         string              `json:"target"`
	PoliciesLoaded int                 `json:"policiesLoaded"`
	Summary        findings.Summary    `json:"summary"`
	Findings       []findings.Finding  `json:"findings"`
	RBACModel      []rbac.SubjectModel `json:"rbacModel,omitempty"`
	CIS            *cis.Scorecard      `json:"cis,omitempty"`
}

// RenderJSON marshals a Result to indented JSON.
func RenderJSON(r Result) ([]byte, error) {
	out := jsonOutput{
		GeneratedAt:    r.GeneratedAt,
		Target:         r.Target,
		PoliciesLoaded: r.PoliciesLoaded,
		Summary:        r.Summary(),
		Findings:       nonNil(r.Findings),
		RBACModel:      r.RBACModel,
		CIS:            r.CIS,
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
