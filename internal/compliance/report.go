package compliance

import "github.com/ivanhahanov/kubectl-audit/internal/findings"

// Status is a control's compliance outcome.
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

// Scorecard is one framework's full compliance report for a scan.
type Scorecard struct {
	ID      string          `json:"id"`
	Title   string          `json:"title"`
	Version string          `json:"version"`
	Results []ControlResult `json:"results"`
}

// BuildScorecard evaluates every control in the mapping against a finding
// set: not-applicable and not-implemented controls are reported as such,
// and every remaining control passes unless a finding references one of
// its policy/native-check IDs.
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
	return Scorecard{ID: mapping.ID, Title: mapping.Title, Version: mapping.Version, Results: results}
}

// FrameworkSummary is one row of the consolidated cross-framework table.
type FrameworkSummary struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Version        string `json:"version"`
	Pass           int    `json:"pass"`
	Fail           int    `json:"fail"`
	NotApplicable  int    `json:"notApplicable"`
	NotImplemented int    `json:"notImplemented"`
	Total          int    `json:"total"`
}

// Summarize condenses one or more scorecards into a per-framework count
// table, for a consolidated multi-framework overview.
func Summarize(scorecards []Scorecard) []FrameworkSummary {
	out := make([]FrameworkSummary, 0, len(scorecards))
	for _, sc := range scorecards {
		s := FrameworkSummary{ID: sc.ID, Title: sc.Title, Version: sc.Version, Total: len(sc.Results)}
		for _, res := range sc.Results {
			switch res.Status {
			case StatusPass:
				s.Pass++
			case StatusFail:
				s.Fail++
			case StatusNotApplicable:
				s.NotApplicable++
			case StatusNotImplemented:
				s.NotImplemented++
			}
		}
		out = append(out, s)
	}
	return out
}
