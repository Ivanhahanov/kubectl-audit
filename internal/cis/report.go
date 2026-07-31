package cis

import "github.com/ivanhahanov/kubectl-audit/internal/findings"

// Status is a CIS control's compliance outcome.
type Status string

const (
	StatusPass           Status = "PASS"
	StatusFail           Status = "FAIL"
	StatusNotApplicable  Status = "NOT_APPLICABLE"
	StatusNotImplemented Status = "NOT_IMPLEMENTED"
)

// ControlResult is one control's row in the scorecard.
type ControlResult struct {
	Control    Control                `json:"control"`
	Status     Status                 `json:"status"`
	FindingIDs []string               `json:"findingIds,omitempty"`
	Resources  []findings.ResourceRef `json:"resources,omitempty"`
	Findings   []findings.Finding     `json:"-"`
}

// Scorecard is the full CIS compliance report for a scan.
type Scorecard struct {
	Version string          `json:"version"`
	Results []ControlResult `json:"results"`
}

// BuildScorecard evaluates every control in the mapping against a finding
// set: not-applicable and not-implemented controls are reported as such,
// and every remaining control passes unless a finding references one of
// its policy/rbac-check IDs.
func BuildScorecard(mapping *Mapping, findingsList []findings.Finding) Scorecard {
	byPolicy := map[string][]findings.Finding{}
	for _, f := range findingsList {
		byPolicy[f.PolicyID] = append(byPolicy[f.PolicyID], f)
	}

	results := make([]ControlResult, 0, len(mapping.Controls))
	for _, c := range mapping.Controls {
		res := ControlResult{Control: c}
		switch {
		case !c.Applicable:
			res.Status = StatusNotApplicable
		case !c.IsImplemented():
			res.Status = StatusNotImplemented
		default:
			var matched []findings.Finding
			for _, id := range c.CheckIDs() {
				matched = append(matched, byPolicy[id]...)
			}
			if len(matched) > 0 {
				res.Status = StatusFail
				res.Findings = matched
				seenResource := map[findings.ResourceRef]bool{}
				for _, f := range matched {
					res.FindingIDs = append(res.FindingIDs, f.ID)
					if !seenResource[f.Resource] {
						seenResource[f.Resource] = true
						res.Resources = append(res.Resources, f.Resource)
					}
				}
			} else {
				res.Status = StatusPass
			}
		}
		results = append(results, res)
	}
	return Scorecard{Version: mapping.Version, Results: results}
}
