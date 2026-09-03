package report_test

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
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
	if !strings.Contains(md, "repeated identically across **3 namespaces**") {
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

// TestGroupByCheck_OutlierMessageDoesNotBlockOtherBucketsFromCollapsing is
// the report-side mirror of the triage TUI's
// TestDedupGroups_OutlierMessageDoesNotBlockOtherRowsFromCollapsing: the
// previous groupByCheck gated collapsing on a per-PolicyID "are ALL of this
// policy's messages identical" check — one outlier finding tripped that
// gate for the ENTIRE policy, so even the 3 genuinely identical findings
// below never collapsed. Bucketing by MessageBucketKey instead means the 3
// identical findings still collapse into one repeated-group row, and the
// outlier just renders as its own separate row alongside it.
func TestGroupByCheck_OutlierMessageDoesNotBlockOtherBucketsFromCollapsing(t *testing.T) {
	msg := func(ns string) string {
		return `ServiceAccount "checker-sa" in namespace "` + ns + `" can read Secrets cluster-wide, via: ClusterRoleBinding "checker-sa-binding-` + ns + `".`
	}
	mk := func(ns, msg, name string) findings.Finding {
		return findings.Finding{
			ID: ns + name, PolicyID: "rbac-analyzer.broad-secrets-access", Title: "Broad Secrets access",
			Severity: findings.SeverityHigh, Category: "rbac",
			Resource: findings.ResourceRef{Kind: "ServiceAccount", Name: name, Namespace: ns},
			Message:  msg,
		}
	}
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			mk("pg-cl-aaa", msg("pg-cl-aaa"), "checker-sa"),
			mk("pg-cl-bbb", msg("pg-cl-bbb"), "checker-sa"),
			mk("pg-cl-ccc", msg("pg-cl-ccc"), "checker-sa"),
			mk("", `Group "kubeadm:cluster-admins" can read Secrets cluster-wide, via: ClusterRoleBinding "kubeadm:cluster-admins" -> ClusterRole "cluster-admin".`, "kubeadm:cluster-admins"),
		},
		NamespaceGroupThreshold: 3,
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(md, "repeated identically") {
		t.Errorf("expected the 3 identical tenant findings to still collapse despite the outlier, got:\n%s", md)
	}
	if !strings.Contains(md, "kubeadm:cluster-admins") {
		t.Errorf("expected the outlier finding to still be shown on its own, got:\n%s", md)
	}
}

// TestGroupByNamePatternCollapsesUUIDSuffixedClusterScopedNames reproduces
// a real bug report: a Capsule-managed cluster with thousands of per-tenant
// Namespace objects named "usersvs-<uuid>" produced one
// psa-analyzer.no-active-enforcement finding per namespace (a native Go
// analyzer whose Resource IS the Namespace object itself — cluster-scoped,
// so it can never repeat under exact-Name matching, since a cluster-scoped
// object's name is unique cluster-wide by construction). GroupByNamePattern
// must catch this by normalizing away the UUID before bucketing, while a
// handful of unrelated, hand-named cluster-scoped resources (argocd,
// cert-manager, ...) must stay listed individually since they share no
// generated-identifier shape with anything.
func TestGroupByNamePatternCollapsesUUIDSuffixedClusterScopedNames(t *testing.T) {
	mk := func(name string) findings.Finding {
		return findings.Finding{
			ID: name, PolicyID: "psa-analyzer.no-active-enforcement", Title: "Namespace has no active Pod Security Admission enforcement",
			Severity: findings.SeverityMedium, Category: "workload-security",
			Resource: findings.ResourceRef{Kind: "Namespace", Name: name},
			Message:  "Namespace does not set the pod-security.kubernetes.io/enforce label.",
		}
	}
	uuids := []string{
		"0004237b-3813-48ce-a48f-3cabdaeccbea",
		"0006e164-99bc-4fac-aaec-079df475fa6b",
		"0007ac46-a472-49fd-baec-9aacfab542c3",
		"0009502c-573a-4e18-8263-b505bf29d705",
	}
	var fs []findings.Finding
	for _, u := range uuids {
		fs = append(fs, mk("usersvs-"+u))
	}
	fs = append(fs, mk("argocd"), mk("cert-manager"))

	r := report.Result{
		GeneratedAt: time.Now(), Target: "test", Findings: fs,
		NamespaceGroupThreshold: 3, GroupByNamePattern: true,
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(md, "Namespace/usersvs-*") {
		t.Errorf("expected the UUID-suffixed namespaces to collapse under the \"usersvs-*\" template, got:\n%s", md)
	}
	if !strings.Contains(md, "repeated identically across **4 objects**") {
		t.Errorf("expected a count of 4 collapsed namespaces, got:\n%s", md)
	}
	if !strings.Contains(md, "argocd") || !strings.Contains(md, "cert-manager") {
		t.Errorf("expected the two unrelated, hand-named namespaces to still be listed, got:\n%s", md)
	}
	// They must NOT have been swept into the same collapsed group as the
	// UUID-suffixed ones.
	if strings.Contains(md, "5 objects") || strings.Contains(md, "6 objects") {
		t.Errorf("expected argocd/cert-manager to stay out of the usersvs-* group, got:\n%s", md)
	}
}

// TestGroupByNamePatternFalseFallsBackToExactMatchOnly covers the opt-out:
// with GroupByNamePattern: false, differently-named cluster-scoped
// resources must never collapse even if they'd share a name-pattern
// template — only an exact, literal Name match collapses (which for
// cluster-scoped resources can never happen in practice, since names are
// cluster-wide unique; the assertion here is just that pattern-matching
// itself doesn't kick in).
func TestGroupByNamePatternFalseFallsBackToExactMatchOnly(t *testing.T) {
	mk := func(name string) findings.Finding {
		return findings.Finding{
			ID: name, PolicyID: "psa-analyzer.no-active-enforcement", Title: "t", Severity: findings.SeverityMedium,
			Category: "workload-security", Resource: findings.ResourceRef{Kind: "Namespace", Name: name},
			Message: "uniform",
		}
	}
	r := report.Result{
		GeneratedAt: time.Now(), Target: "test",
		Findings: []findings.Finding{
			mk("usersvs-0004237b-3813-48ce-a48f-3cabdaeccbea"),
			mk("usersvs-0006e164-99bc-4fac-aaec-079df475fa6b"),
			mk("usersvs-0007ac46-a472-49fd-baec-9aacfab542c3"),
		},
		NamespaceGroupThreshold: 3, GroupByNamePattern: false,
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if strings.Contains(md, "repeated identically") {
		t.Errorf("expected GroupByNamePattern: false to disable pattern-based collapsing, got:\n%s", md)
	}
}

// TestGroupAffectedResourcesCapsExampleList guards against a huge collapsed
// group (the reported cluster had 9351 matching namespaces) printing every
// single example — that would defeat the entire point of collapsing.
func TestGroupAffectedResourcesCapsExampleList(t *testing.T) {
	mk := func(name string) findings.Finding {
		return findings.Finding{
			ID: name, PolicyID: "psa-analyzer.no-active-enforcement", Title: "t", Severity: findings.SeverityMedium,
			Category: "workload-security", Resource: findings.ResourceRef{Kind: "Namespace", Name: name},
			Message: "uniform",
		}
	}
	var fs []findings.Finding
	for i := 0; i < 50; i++ {
		fs = append(fs, mk(fmt.Sprintf("usersvs-%08x-0000-4000-8000-%012x", i, i)))
	}
	r := report.Result{
		GeneratedAt: time.Now(), Target: "test", Findings: fs,
		NamespaceGroupThreshold: 3, GroupByNamePattern: true,
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(md, "repeated identically across **50 objects**") {
		t.Errorf("expected the total count (50) to be shown even though examples are capped, got:\n%s", md)
	}
	if !strings.Contains(md, "more)") {
		t.Errorf("expected a \"(+N more)\" truncation marker, got:\n%s", md)
	}
	if strings.Count(md, "usersvs-") > 9 { // 8 examples + the collapsed "usersvs-*" label itself
		t.Errorf("expected the example list to be capped well below 50 entries, got:\n%s", md)
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
