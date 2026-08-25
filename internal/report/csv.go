package report

import (
	"bytes"
	"encoding/csv"
	"os"
	"strings"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

var csvHeader = []string{
	"severity", "policyId", "title", "category", "cis",
	"kind", "namespace", "name", "apiVersion",
	"message", "remediation", "source", "id", "verificationSteps",
}

// RenderCSV renders findings as CSV, one row per finding, sorted by
// severity (most severe first) — the same order the Markdown report groups
// by. Meant for loading into a spreadsheet to sort/filter/pivot/assign
// owners, which JSON isn't a great fit for without extra tooling.
//
// Unlike the JSON and Markdown outputs, this intentionally carries only
// findings: the RBAC role model and compliance scorecards are a different
// shape (not one-row-per-finding) and don't belong in the same flat table.
func RenderCSV(r Result) ([]byte, error) {
	sorted := append([]findings.Finding{}, r.Findings...)
	findings.SortBySeverity(sorted)

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(csvHeader); err != nil {
		return nil, err
	}
	for _, f := range sorted {
		row := []string{
			string(f.Severity), f.PolicyID, f.Title, f.Category, strings.Join(f.CIS, ";"),
			f.Resource.Kind, f.Resource.Namespace, f.Resource.Name, f.Resource.APIVersion,
			f.Message, f.Remediation, f.Source, f.ID, f.VerificationSteps,
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteCSV renders and writes findings.csv to path.
func WriteCSV(path string, r Result) error {
	data, err := RenderCSV(r)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
