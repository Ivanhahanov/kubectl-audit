package report_test

import (
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
	md := report.RenderMarkdown(report.Result{GeneratedAt: time.Now(), Target: "test"})
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
	md := report.RenderMarkdown(r)
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
