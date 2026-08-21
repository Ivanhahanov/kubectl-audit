package report_test

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/report"
	"github.com/ivanhahanov/kubectl-audit/internal/thirdparty"
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

// TestRenderMarkdownEscapesDetectedComponentName guards a real Markdown
// table-injection bug found by an adversarial audit: the Detected
// Components table rendered {{ .Name }} directly, without the escapeCell
// helper every other free-text table cell in this template uses — a
// component name containing a raw "|" shifts the table's columns in the
// rendered output. Name here comes from internal/thirdparty/components.yaml
// (repo-controlled) or a user's own audit.yaml components.extra (self-
// inflicted if wrong), never a raw object name from the scanned cluster —
// but the fix is one line and worth a permanent regression test regardless.
func TestRenderMarkdownEscapesDetectedComponentName(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		DetectedComponents: []thirdparty.Detection{
			{Component: thirdparty.Component{Name: "Evil|Component", Category: thirdparty.CategoryApplication}, LabelCount: 1},
		},
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if strings.Contains(md, "| Evil|Component |") {
		t.Errorf("expected the raw \"|\" in the component name to be escaped, not rendered as a literal table-cell separator, got:\n%s", md)
	}
	if !strings.Contains(md, `Evil\|Component`) {
		t.Errorf("expected the component name to appear escaped (Evil\\|Component), got:\n%s", md)
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

// namespacedFinding builds a finding with a uniform, VAP-style static
// message (the shape TestNamespaceGroupThreshold* below rely on to trigger
// collapsing) — same PolicyID/Title/Message every time, only the namespace
// varies, mimicking a per-tenant-namespace pattern (e.g. Capsule) that
// deploys the same manifest into every tenant's namespace.
func namespacedFinding(ns string) findings.Finding {
	return findings.Finding{
		ID: ns, PolicyID: "workload.no-latest-tag", Title: "Uses the latest tag", Severity: findings.SeverityHigh,
		Category: "workload-security", Resource: findings.ResourceRef{Kind: "Deployment", Name: "app", Namespace: ns},
		Message: "container image uses the latest tag",
	}
}

// TestNamespaceGroupThresholdCollapsesRepeatedNamespaces guards the
// multi-tenant noise-reduction feature: the same Kind+Name+Message
// repeated across at least NamespaceGroupThreshold distinct namespaces
// must render as one collapsed row naming every affected namespace,
// instead of one bullet line per namespace.
func TestNamespaceGroupThresholdCollapsesRepeatedNamespaces(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			namespacedFinding("tenant-a"),
			namespacedFinding("tenant-b"),
			namespacedFinding("tenant-c"),
		},
		NamespaceGroupThreshold: 3,
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(md, "repeated identically in **3 namespaces**") {
		t.Errorf("expected a collapsed repeat-group row, got:\n%s", md)
	}
	if !strings.Contains(md, "tenant-a, tenant-b, tenant-c") {
		t.Errorf("expected all three namespaces named in the collapsed row, got:\n%s", md)
	}
	// Exactly one row, not one bullet per namespace.
	if n := strings.Count(md, "Deployment/app"); n != 1 {
		t.Errorf("expected exactly one collapsed row (not one per namespace), got %d occurrences in:\n%s", n, md)
	}
}

// TestNamespaceGroupThresholdBelowThresholdNotCollapsed is the
// complementary case: fewer repeats than the threshold must still list
// each namespace individually, same as before this feature existed.
func TestNamespaceGroupThresholdBelowThresholdNotCollapsed(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			namespacedFinding("tenant-a"),
			namespacedFinding("tenant-b"),
		},
		NamespaceGroupThreshold: 3,
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if strings.Contains(md, "repeated identically") {
		t.Errorf("expected no collapsing below the threshold, got:\n%s", md)
	}
	if !strings.Contains(md, "/Deployment tenant-a/app") || !strings.Contains(md, "/Deployment tenant-b/app") {
		t.Errorf("expected both namespaces listed individually, got:\n%s", md)
	}
}

// TestNamespaceGroupThresholdZeroDisablesCollapsing covers the explicit
// opt-out (also report.Result{}'s zero value, exercised by every other
// test in this file that doesn't set NamespaceGroupThreshold) — even with
// enough repeats to otherwise qualify, nothing collapses.
func TestNamespaceGroupThresholdZeroDisablesCollapsing(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			namespacedFinding("tenant-a"),
			namespacedFinding("tenant-b"),
			namespacedFinding("tenant-c"),
		},
		NamespaceGroupThreshold: 0,
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if strings.Contains(md, "repeated identically") {
		t.Errorf("expected NamespaceGroupThreshold: 0 to disable collapsing entirely, got:\n%s", md)
	}
}

// TestNamespaceGroupThresholdNeverCollapsesNonUniformMessages guards the
// safety scope of this feature: a check whose message differs per finding
// (true for native analyzers like RBAC/PSS/control-plane) must never be
// collapsed, even if the same Kind+Name+message combination happens to
// repeat — collapsing there could hide genuinely different per-resource
// detail.
func TestNamespaceGroupThresholdNeverCollapsesNonUniformMessages(t *testing.T) {
	mk := func(ns, msg string) findings.Finding {
		f := namespacedFinding(ns)
		f.Message = msg
		return f
	}
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			mk("tenant-a", "specific detail A"),
			mk("tenant-b", "specific detail B"),
			mk("tenant-c", "specific detail C"),
		},
		NamespaceGroupThreshold: 3,
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if strings.Contains(md, "repeated identically") {
		t.Errorf("expected no collapsing when findings' messages differ, got:\n%s", md)
	}
	for _, want := range []string{"specific detail A", "specific detail B", "specific detail C"} {
		if !strings.Contains(md, want) {
			t.Errorf("expected each finding's distinct message to still be shown in full, got:\n%s", md)
		}
	}
}

// TestNamespaceGroupThresholdIgnoresClusterScopedResources guards against
// grouping cluster-scoped findings (Namespace == "") by mistake — they
// can't repeat "per namespace" by definition, and must always render
// individually regardless of the threshold.
func TestNamespaceGroupThresholdIgnoresClusterScopedResources(t *testing.T) {
	// Same Kind+Name+Message (the exact shape that would collapse if
	// namespaced) but Namespace == "" — three distinct findings, e.g. one
	// per policy variant/discriminator, all against the same cluster-scoped
	// object name.
	mk := func(id string) findings.Finding {
		return findings.Finding{
			ID: id, PolicyID: "rbac.cluster-admin-binding", Title: "cluster-admin bound broadly", Severity: findings.SeverityCritical,
			Category: "rbac", Resource: findings.ResourceRef{Kind: "ClusterRoleBinding", Name: "cluster-admin-binding"},
			Message: "grants cluster-admin",
		}
	}
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			mk("a"), mk("b"), mk("c"),
		},
		NamespaceGroupThreshold: 3,
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if strings.Contains(md, "repeated identically") {
		t.Errorf("expected cluster-scoped findings to never collapse, got:\n%s", md)
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
