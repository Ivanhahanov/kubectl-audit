package report_test

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/report"
)

func TestRenderJSONEmptyResult(t *testing.T) {
	data, err := report.RenderJSON(report.Result{GeneratedAt: time.Now(), Target: "test"})
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("RenderJSON produced invalid JSON: %v", err)
	}
	for _, key := range []string{"generatedAt", "target", "summary", "findings"} {
		if _, ok := out[key]; !ok {
			t.Errorf("expected JSON output to contain %q, got %v", key, out)
		}
	}
	if findingsArr, ok := out["findings"].([]interface{}); !ok || findingsArr == nil {
		t.Errorf("expected findings to be an empty array, not null: %v", out["findings"])
	}
}

func TestRenderJSONWithFindings(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Severity: findings.SeverityHigh, Category: "workload-security",
				Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "default"}, Message: "bad"},
		},
	}
	data, err := report.RenderJSON(r)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	summary, ok := out["summary"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected summary object, got %v", out["summary"])
	}
	if summary["HIGH"] != float64(1) {
		t.Errorf("expected summary.HIGH == 1, got %v", summary["HIGH"])
	}
}

func TestRenderMarkdownEmptyResult(t *testing.T) {
	md, err := report.RenderMarkdown(report.Result{GeneratedAt: time.Now(), Target: "test"}, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(md, "No findings.") {
		t.Errorf("expected 'No findings.' in an empty report, got:\n%s", md)
	}
}

func TestRenderMarkdownWithFindings(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
				Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "default"}, Message: "bad thing happened"},
		},
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(md, "### HIGH") {
		t.Errorf("expected a HIGH severity section, got:\n%s", md)
	}
	if !strings.Contains(md, "[workload.x]") {
		t.Errorf("expected the policy ID in the finding heading, got:\n%s", md)
	}
	if !strings.Contains(md, "bad thing happened") {
		t.Errorf("expected the finding message, got:\n%s", md)
	}
}

func TestRenderMarkdownSourceSuffix(t *testing.T) {
	finding := findings.Finding{
		ID: "1", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
		Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "default"}, Message: "bad thing happened",
		Source: "/manifests/a.yaml",
	}

	single := report.Result{GeneratedAt: time.Now(), Target: "test", Findings: []findings.Finding{finding}, MultipleSources: false}
	md, err := report.RenderMarkdown(single, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if strings.Contains(md, "/manifests/a.yaml") {
		t.Errorf("expected no per-finding source suffix with a single source (redundant with Target), got:\n%s", md)
	}

	multi := report.Result{GeneratedAt: time.Now(), Target: "test", Findings: []findings.Finding{finding}, MultipleSources: true}
	md, err = report.RenderMarkdown(multi, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(md, "/manifests/a.yaml") {
		t.Errorf("expected the per-finding source suffix when MultipleSources is true, got:\n%s", md)
	}
}

func TestRenderCSV(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityLow, Category: "workload-security",
				CIS: []string{"5.2.1", "5.2.2"}, Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "default"},
				Message: "a, message with, commas", Remediation: "fix it"},
			{ID: "2", PolicyID: "workload.y", Title: "Worse thing", Severity: findings.SeverityCritical, Category: "workload-security",
				Resource: findings.ResourceRef{Kind: "Pod", Name: "q"}, Message: "urgent"},
		},
	}
	data, err := report.RenderCSV(r)
	if err != nil {
		t.Fatalf("RenderCSV: %v", err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if err != nil {
		t.Fatalf("RenderCSV produced invalid CSV: %v", err)
	}
	if len(rows) != 3 { // header + 2 findings
		t.Fatalf("expected 3 rows, got %d: %v", len(rows), rows)
	}
	if rows[0][0] != "severity" {
		t.Errorf("expected a header row starting with 'severity', got %v", rows[0])
	}
	// Sorted most-severe first: CRITICAL before LOW.
	if rows[1][0] != "CRITICAL" || rows[2][0] != "LOW" {
		t.Errorf("expected CRITICAL then LOW, got %q then %q", rows[1][0], rows[2][0])
	}
	// The comma-containing message must round-trip intact through quoting.
	if rows[2][9] != "a, message with, commas" {
		t.Errorf("expected the message field to round-trip through CSV quoting, got %q", rows[2][9])
	}
}

func TestRenderMarkdownCustomTemplate(t *testing.T) {
	r := report.Result{GeneratedAt: time.Now(), Target: "my-cluster"}
	md, err := report.RenderMarkdown(r, "Custom report for {{ .Target }}\n")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if md != "Custom report for my-cluster\n" {
		t.Errorf("expected the custom template to fully replace the default output, got:\n%s", md)
	}
}
