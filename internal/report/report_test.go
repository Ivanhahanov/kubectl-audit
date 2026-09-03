package report_test

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/compliance"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/rbac"
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

// TestRenderMarkdown_NoSeverityJumpTable guards the removal of the
// per-severity "Policy ID/Title/Category/Affected" mini-table: it
// duplicated the same three fields shown immediately below in each
// check's own detail card, adding clutter without adding information —
// removed per direct feedback. The check's own anchor stays (still a
// valid link target, just nothing in-report links to it via a jump table
// anymore).
func TestRenderMarkdown_NoSeverityJumpTable(t *testing.T) {
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
	if strings.Contains(md, "| Policy ID | Title | Category | Affected |") {
		t.Errorf("expected the per-severity jump table removed, got:\n%s", md)
	}
	if !strings.Contains(md, `<a id="check-workload-x"></a>`) {
		t.Errorf("expected the check's own anchor to still be present, got:\n%s", md)
	}
}

// TestRenderMarkdown_CollapsesLargeCheckByDefault is the compact-layout
// scroll-reduction fix: a check with more than checkCollapseThreshold
// findings wraps its Affected resources in a <details> block instead of
// dumping every row inline — but every row is still present, just behind a
// click, so no information is lost.
func TestRenderMarkdown_CollapsesLargeCheckByDefault(t *testing.T) {
	// Distinct messages that don't embed their own namespace as a
	// standalone word (NormalizedMessage would strip that, bucketing them
	// together — not what this test is exercising) so each finding lands
	// in its own MessageGroup and stays individually visible.
	mk := func(ns string, n int) findings.Finding {
		return findings.Finding{
			ID: ns, PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
			Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: ns}, Message: fmt.Sprintf("finding number %d", n),
		}
	}
	var fs []findings.Finding
	namespaces := []string{"tenant-0", "tenant-1", "tenant-2", "tenant-3", "tenant-4", "tenant-5", "tenant-6", "tenant-7", "tenant-8"}
	for i, ns := range namespaces { // 9 > checkCollapseThreshold (8)
		fs = append(fs, mk(ns, i))
	}
	r := report.Result{GeneratedAt: time.Now(), Target: "test", Findings: fs}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(md, "<details>") || !strings.Contains(md, "</details>") {
		t.Errorf("expected a large check's Affected resources wrapped in <details>, got:\n%s", md)
	}
	for i := range namespaces {
		want := fmt.Sprintf("finding number %d", i)
		if !strings.Contains(md, want) {
			t.Errorf("expected every finding's message still present (behind <details>), missing %q, got:\n%s", want, md)
		}
	}
}

// TestRenderMarkdown_SmallCheckNotCollapsed guards the complementary case:
// a check at or below checkCollapseThreshold renders fully open, no click
// needed for the common (small) case.
func TestRenderMarkdown_SmallCheckNotCollapsed(t *testing.T) {
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
	if strings.Contains(md, "<details>") {
		t.Errorf("expected a small check to render fully open, not wrapped in <details>, got:\n%s", md)
	}
}

// TestRenderMarkdown_KnowledgeBaseOverridesCheckContent is the report-side
// half of the knowledge-base feature: an organization's own
// Title/Category/Remediation for a check (already used by the triage TUI
// and Jira ticket rendering, see internal/triage.Resolve) must also show
// up in the static report, and blend in under the same plain labels — no
// "(org)"/"(knowledge base)" suffix, matching the triage TUI's existing
// precedent (TestDetailText_NoKnowledgeBaseLabelSuffix).
func TestRenderMarkdown_KnowledgeBaseOverridesCheckContent(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Title: "Default title", Severity: findings.SeverityHigh, Category: "workload-security",
				Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "default"}, Message: "bad thing happened", Remediation: "default remediation"},
		},
		KnowledgeBase: map[string]findings.KnowledgeBaseEntry{
			"workload.x": {Title: "Наш заголовок", Category: "custom-category", Remediation: "Наша рекомендация"},
		},
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	for _, want := range []string{"Наш заголовок", "custom-category", "Наша рекомендация"} {
		if !strings.Contains(md, want) {
			t.Errorf("expected the knowledge-base override %q to appear, got:\n%s", want, md)
		}
	}
	for _, notWant := range []string{"Default title", "default remediation", "(org", "knowledge base)"} {
		if strings.Contains(md, notWant) {
			t.Errorf("expected %q not to appear (overridden or no source annotation), got:\n%s", notWant, md)
		}
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
	if !strings.Contains(md, "| Deployment/app | tenant-a |") || !strings.Contains(md, "| Deployment/app | tenant-b |") {
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

// TestRenderConfluence_UsesWikiMarkupNotMarkdown is the smoke test for the
// Confluence Server/Data Center output: real Confluence wiki-markup syntax
// (h1./h2./h3., ||table headers||, *bold*) must appear, and the equivalent
// Markdown constructs (##, **bold**, | table |) must not — the exact
// rendering mismatch this format exists to avoid (see the Jira Server/DC
// wiki-markup work this format is modeled on).
func TestRenderConfluence_UsesWikiMarkupNotMarkdown(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
				Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "default"}, Message: "bad thing happened", Remediation: "fix it"},
		},
	}
	out, err := report.RenderConfluence(r, "")
	if err != nil {
		t.Fatalf("RenderConfluence: %v", err)
	}
	for _, want := range []string{"h1. Kubernetes Security Audit Report", "h2. Summary", "h3.", "||Field||Value||", "|Category|workload-security|", "bad thing happened", "{toc"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected Confluence wiki markup %q, got:\n%s", want, out)
		}
	}
	for _, notWant := range []string{"## ", "**Category:**", "| Policy ID | Title", "<details>", "<summary>", `<a id="`} {
		if strings.Contains(out, notWant) {
			t.Errorf("expected no Markdown/HTML syntax %q in Confluence output, got:\n%s", notWant, out)
		}
	}
}

// TestRenderConfluence_CollapsesLargeCheckWithExpandMacro is the Confluence
// equivalent of TestRenderMarkdown_CollapsesLargeCheckByDefault — {expand}
// is Confluence's collapsible-section macro, the direct analog of
// Markdown's <details>.
func TestRenderConfluence_CollapsesLargeCheckWithExpandMacro(t *testing.T) {
	mk := func(ns string, n int) findings.Finding {
		return findings.Finding{
			ID: ns, PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
			Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: ns}, Message: fmt.Sprintf("finding number %d", n),
		}
	}
	var fs []findings.Finding
	for i := 0; i < 9; i++ { // > checkCollapseThreshold (8)
		fs = append(fs, mk(fmt.Sprintf("tenant-%d", i), i))
	}
	r := report.Result{GeneratedAt: time.Now(), Target: "test", Findings: fs}
	out, err := report.RenderConfluence(r, "")
	if err != nil {
		t.Fatalf("RenderConfluence: %v", err)
	}
	if !strings.Contains(out, "{expand:9 findings") {
		t.Errorf("expected a large check wrapped in an {expand} macro, got:\n%s", out)
	}
	for i := 0; i < 9; i++ {
		want := fmt.Sprintf("finding number %d", i)
		if !strings.Contains(out, want) {
			t.Errorf("expected every finding still present behind {expand}, missing %q, got:\n%s", want, out)
		}
	}
}

// TestRenderConfluence_CustomTemplate mirrors
// TestRenderMarkdownCustomTemplate: --confluence-template must fully
// replace the built-in template.
func TestRenderConfluence_CustomTemplate(t *testing.T) {
	r := report.Result{GeneratedAt: time.Now(), Target: "my-cluster"}
	out, err := report.RenderConfluence(r, "Custom report for {{ .Target }}\n")
	if err != nil {
		t.Fatalf("RenderConfluence: %v", err)
	}
	if out != "Custom report for my-cluster\n" {
		t.Errorf("expected the custom template to fully replace the default output, got:\n%s", out)
	}
}

// TestRenderMarkdown_RussianTemplate is the Part C smoke test: the report
// skeleton (headings, labels) renders in Russian, and severity values
// translate via severityRU rather than leaking the raw English constant.
func TestRenderMarkdown_RussianTemplate(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
				Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "default"}, Message: "bad thing happened"},
		},
	}
	md, err := report.RenderMarkdown(r, report.RussianTemplate())
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	for _, want := range []string{"Отчёт аудита безопасности Kubernetes", "## Сводка", "### Высокий", "Затронутые ресурсы", "bad thing happened"} {
		if !strings.Contains(md, want) {
			t.Errorf("expected Russian template output %q, got:\n%s", want, md)
		}
	}
	if strings.Contains(md, "### HIGH") {
		t.Errorf("expected the severity heading translated, not the raw English constant, got:\n%s", md)
	}
}

// TestRenderMarkdown_RussianTemplate_KnowledgeBaseFieldsRenderAsTemplates
// is the exact scenario the resolveCheckKB templating bugfix guards: the
// bundled starter-ru.yaml knowledge base writes Remediation as a Go
// template referencing {{.Finding.Resource...}} — it must render
// substituted, not leak literal "{{...}}" syntax into the report.
func TestRenderMarkdown_RussianTemplate_KnowledgeBaseFieldsRenderAsTemplates(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
				Resource: findings.ResourceRef{Kind: "Deployment", Name: "app", Namespace: "ns"}, Message: "bad thing happened"},
		},
		KnowledgeBase: map[string]findings.KnowledgeBaseEntry{
			"workload.x": {Remediation: `Почините {{.Finding.Resource.Kind}} "{{.Finding.Resource.Name}}".`},
		},
	}
	md, err := report.RenderMarkdown(r, report.RussianTemplate())
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(md, `Почините Deployment "app".`) {
		t.Errorf("expected the knowledge-base template rendered against the finding, got:\n%s", md)
	}
	if strings.Contains(md, "{{.Finding") {
		t.Errorf("expected no literal Go template syntax leaked into the report, got:\n%s", md)
	}
}

// TestRenderMarkdown_SingleResourceMessageGroupRendersInline is the fix
// for a real report: a message shared by exactly one resource used to
// still get a full "| Resource | Namespace |" table for that one row —
// disproportionately heavy for a single piece of information. A singleton
// MessageGroup now renders as one inline line instead.
func TestRenderMarkdown_SingleResourceMessageGroupRendersInline(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
				Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "ns"}, Message: "only one resource affected"},
		},
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if strings.Contains(md, "| Resource | Namespace |") {
		t.Errorf("expected no table for a single-resource message group, got:\n%s", md)
	}
	if !strings.Contains(md, "only one resource affected — Pod/p (ns)") {
		t.Errorf("expected the message and resource on one inline line, got:\n%s", md)
	}
}

// TestRenderConfluence_SingleResourceMessageGroupRendersInline mirrors
// TestRenderMarkdown_SingleResourceMessageGroupRendersInline for the
// Confluence template.
func TestRenderConfluence_SingleResourceMessageGroupRendersInline(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
				Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "ns"}, Message: "only one resource affected"},
		},
	}
	out, err := report.RenderConfluence(r, "")
	if err != nil {
		t.Fatalf("RenderConfluence: %v", err)
	}
	if strings.Contains(out, "||Resource||Namespace||") {
		t.Errorf("expected no table for a single-resource message group, got:\n%s", out)
	}
	if !strings.Contains(out, "only one resource affected — Pod/p (ns)") {
		t.Errorf("expected the message and resource on one inline line, got:\n%s", out)
	}
}

// TestRenderConfluence_SeverityBadgeOnItsOwnLine guards the fix for a real
// report: {status:...} placed inline on the same "h3." line as the
// heading text didn't render as a lozenge in real Confluence — macros are
// reliable on their own line/paragraph, not concatenated into heading
// text.
func TestRenderConfluence_SeverityBadgeOnItsOwnLine(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityCritical, Category: "workload-security",
				Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "ns"}, Message: "bad"},
		},
	}
	out, err := report.RenderConfluence(r, "")
	if err != nil {
		t.Fatalf("RenderConfluence: %v", err)
	}
	if strings.Contains(out, "h3. {status:") {
		t.Errorf("expected the {status} macro NOT concatenated into the h3. heading line, got:\n%s", out)
	}
	if !strings.Contains(out, "h3. CRITICAL (1)\n\n{status:colour=Red|title=CRITICAL}") {
		t.Errorf("expected the {status} macro on its own line right after the heading, got:\n%s", out)
	}
}

// TestRenderMarkdown_FailingControlsSectionCollapsed and its Confluence
// counterpart guard the fix for a real report: "Failing controls —
// affected resources" duplicates the Findings section (same findings,
// grouped by control instead of by check) and could get enormous on a
// large cluster. It now collapses behind <details>/{expand} like every
// other long section, instead of always being fully expanded.
func failingControlResult() report.Result {
	f := findings.Finding{
		ID: "1", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
		Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "ns"}, Message: "bad",
	}
	sc := compliance.Scorecard{
		ID: "cis", Title: "CIS", Version: "1.0",
		Results: []compliance.ControlResult{
			{
				Control:  compliance.Control{ID: "1.1", Title: "Some control", PolicyIDs: []string{"workload.x"}},
				Status:   compliance.StatusFail,
				Findings: []findings.Finding{f},
			},
		},
	}
	return report.Result{
		GeneratedAt: time.Now(), Target: "test", Findings: []findings.Finding{f},
		Frameworks: []compliance.Scorecard{sc},
	}
}

func TestRenderMarkdown_FailingControlsSectionCollapsed(t *testing.T) {
	md, err := report.RenderMarkdown(failingControlResult(), "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(md, "<summary>Failing controls — affected resources (1) — click to expand</summary>") {
		t.Errorf("expected the failing-controls section collapsed behind <details>, got:\n%s", md)
	}
	if !strings.Contains(md, "Some control") {
		t.Errorf("expected the control detail still present (behind <details>), got:\n%s", md)
	}
}

func TestRenderConfluence_FailingControlsSectionCollapsed(t *testing.T) {
	out, err := report.RenderConfluence(failingControlResult(), "")
	if err != nil {
		t.Fatalf("RenderConfluence: %v", err)
	}
	if !strings.Contains(out, "{expand:Failing controls — affected resources (1)}") {
		t.Errorf("expected the failing-controls section collapsed behind {expand}, got:\n%s", out)
	}
	if !strings.Contains(out, "Some control") {
		t.Errorf("expected the control detail still present (behind {expand}), got:\n%s", out)
	}
}

// TestRenderConfluence_EscapesCurlyBracesInFreeText is the regression
// test for a real report: a finding's own Message/Remediation can contain
// literal "{" from describing YAML/JSON-shaped content (an ArgoCD policy
// quotes {group: "*", kind: "*"} — see
// policies/thirdparty/argocd/appproject-wildcard-cluster-resources.yaml).
// Confluence's wiki-markup parser reads "{group: ..." as an attempted
// macro invocation named "group" and renders "Unknown macro: group"
// instead of the literal text. Every free-text field must escape "{"/"}"
// for Confluence (Markdown has no such risk and must NOT escape them).
func TestRenderConfluence_EscapesCurlyBracesInFreeText(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "argocd.x", Title: "Bad", Severity: findings.SeverityHigh, Category: "workload-security",
				Resource:    findings.ResourceRef{Kind: "AppProject", Name: "default", Namespace: "argocd"},
				Message:     `includes {group: "*", kind: "*"}, allowing arbitrary resources.`,
				Remediation: `Restrict to specific {group, kind} pairs.`,
			},
		},
	}
	out, err := report.RenderConfluence(r, "")
	if err != nil {
		t.Fatalf("RenderConfluence: %v", err)
	}
	if !strings.Contains(out, `\{group: "*", kind: "*"\}`) {
		t.Errorf("expected the Message's curly braces escaped, got:\n%s", out)
	}
	if !strings.Contains(out, `\{group, kind\}`) {
		t.Errorf("expected the Remediation's curly braces escaped, got:\n%s", out)
	}

	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if strings.Contains(md, `\{`) {
		t.Errorf("expected Markdown NOT to escape curly braces (no macro-parsing risk there), got:\n%s", md)
	}
}

// TestRenderMarkdown_MessageNotItalicized and its Confluence counterpart
// guard a readability fix: wrapping a whole finding Message (often a full
// sentence, sometimes a long one) in italics is hard to read at that
// length — italics work for a short emphasis, not a paragraph. The
// message now renders as plain text.
func TestRenderMarkdown_MessageNotItalicized(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
				Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "default"}, Message: "bad thing happened"},
			{ID: "2", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
				Resource: findings.ResourceRef{Kind: "Pod", Name: "q", Namespace: "default"}, Message: "a different bad thing"},
		},
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if strings.Contains(md, "_bad thing happened_") || strings.Contains(md, "_a different bad thing_") {
		t.Errorf("expected the message NOT wrapped in italics, got:\n%s", md)
	}
	if !strings.Contains(md, "bad thing happened") {
		t.Errorf("expected the message text still present, got:\n%s", md)
	}
}

func TestRenderConfluence_MessageNotItalicized(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
				Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "default"}, Message: "bad thing happened"},
			{ID: "2", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
				Resource: findings.ResourceRef{Kind: "Pod", Name: "q", Namespace: "default"}, Message: "a different bad thing"},
		},
	}
	out, err := report.RenderConfluence(r, "")
	if err != nil {
		t.Fatalf("RenderConfluence: %v", err)
	}
	if strings.Contains(out, "_bad thing happened_") || strings.Contains(out, "_a different bad thing_") {
		t.Errorf("expected the message NOT wrapped in italics, got:\n%s", out)
	}
	if !strings.Contains(out, "bad thing happened") {
		t.Errorf("expected the message text still present, got:\n%s", out)
	}
}

// TestRenderMarkdown_RBACModelCollapsed and its Confluence counterpart
// guard a real complaint: the RBAC Role Model table lists every subject's
// full permission set and gets very large — it now collapses behind
// <details>/{expand} like every other long section, instead of always
// being fully expanded.
func rbacModelResult() report.Result {
	return report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		RBACModel: []rbac.SubjectModel{
			{
				Subject:     rbac.SubjectKey{Kind: "ServiceAccount", Name: "sa", Namespace: "ns"},
				Permissions: []string{"get secrets", "list pods"},
			},
		},
	}
}

func TestRenderMarkdown_RBACModelCollapsed(t *testing.T) {
	md, err := report.RenderMarkdown(rbacModelResult(), "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(md, "<summary>1 subjects — click to expand</summary>") {
		t.Errorf("expected the RBAC model collapsed behind <details>, got:\n%s", md)
	}
	if !strings.Contains(md, "get secrets") {
		t.Errorf("expected the permissions still present (behind <details>), got:\n%s", md)
	}
}

func TestRenderConfluence_RBACModelCollapsed(t *testing.T) {
	out, err := report.RenderConfluence(rbacModelResult(), "")
	if err != nil {
		t.Fatalf("RenderConfluence: %v", err)
	}
	if !strings.Contains(out, "{expand:1 subjects — click to expand}") {
		t.Errorf("expected the RBAC model collapsed behind {expand}, got:\n%s", out)
	}
	if !strings.Contains(out, "get secrets") {
		t.Errorf("expected the permissions still present (behind {expand}), got:\n%s", out)
	}
}

// TestRenderConfluence_DetectedComponentCategoryNamedType is the
// regression test for a real crash: thirdparty.Detection.Category is
// thirdparty.Category, a named string type, not string. escapeCell used
// to take a plain `string` parameter — Go templates require an exact type
// match for a function's declared parameter, so escapeCell .Category
// failed at execution with "wrong type for value; expected string; got
// thirdparty.Category" the moment Confluence output was rendered for a
// scan with any detected component. escapeCell/escapeConfluenceCell now
// take `any` and stringify internally.
func TestRenderConfluence_DetectedComponentCategoryNamedType(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		DetectedComponents: []thirdparty.Detection{
			{Component: thirdparty.Component{Name: "cert-manager", Category: thirdparty.CategorySystem}, LabelCount: 3},
		},
	}
	out, err := report.RenderConfluence(r, "")
	if err != nil {
		t.Fatalf("RenderConfluence: %v", err)
	}
	if !strings.Contains(out, "|cert-manager|System|") {
		t.Errorf("expected the detected component row rendered, got:\n%s", out)
	}
}

// TestRenderMarkdown_HeaderTableWithOwnerAndClusterEndpoint and its
// Confluence/Russian counterparts guard the header-info-as-a-table
// redesign, plus the two new optional fields (ClusterEndpoint, Owner) —
// shown only when set, same convention as ClusterVersion.
func headerFieldsResult() report.Result {
	return report.Result{
		GeneratedAt:     time.Now(),
		Target:          "test-cluster",
		ClusterVersion:  "v1.29.4",
		ClusterEndpoint: "https://10.0.5.2:6443",
		Owner:           "platform-security-team",
	}
}

func TestRenderMarkdown_HeaderTableWithOwnerAndClusterEndpoint(t *testing.T) {
	md, err := report.RenderMarkdown(headerFieldsResult(), "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	for _, want := range []string{"| Field | Value |", "| Cluster endpoint | https://10.0.5.2:6443 |", "| Owner | platform-security-team |"} {
		if !strings.Contains(md, want) {
			t.Errorf("expected %q in the header table, got:\n%s", want, md)
		}
	}
}

func TestRenderMarkdown_HeaderOmitsOwnerAndEndpointWhenUnset(t *testing.T) {
	md, err := report.RenderMarkdown(report.Result{GeneratedAt: time.Now(), Target: "test"}, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if strings.Contains(md, "Cluster endpoint") || strings.Contains(md, "Owner") {
		t.Errorf("expected no Cluster endpoint/Owner row when unset, got:\n%s", md)
	}
}

func TestRenderConfluence_HeaderTableWithOwnerAndClusterEndpoint(t *testing.T) {
	out, err := report.RenderConfluence(headerFieldsResult(), "")
	if err != nil {
		t.Fatalf("RenderConfluence: %v", err)
	}
	for _, want := range []string{"||Field||Value||", "|Cluster endpoint|https://10.0.5.2:6443|", "|Owner|platform-security-team|"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the header table, got:\n%s", want, out)
		}
	}
}

// TestRenderMarkdown_ContextSectionMergesScopeAndDetectedComponents
// guards the section merge: Scope and Detected Components used to be two
// separate top-level sections; they're now one "Context" section with
// Detected Components as a subsection, per direct feedback.
func TestRenderMarkdown_ContextSectionMergesScopeAndDetectedComponents(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		DetectedComponents: []thirdparty.Detection{
			{Component: thirdparty.Component{Name: "cert-manager", Category: thirdparty.CategorySystem}, LabelCount: 3},
		},
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(md, `<a id="context"></a>`) || !strings.Contains(md, "## Context") {
		t.Errorf("expected a single Context section, got:\n%s", md)
	}
	if strings.Contains(md, "\n## Detected Components") {
		t.Errorf("expected Detected Components as a subsection (###), not its own top-level section, got:\n%s", md)
	}
	if !strings.Contains(md, "### Detected Components") {
		t.Errorf("expected Detected Components as a subsection under Context, got:\n%s", md)
	}
	if strings.Contains(md, "internal/thirdparty") || strings.Contains(md, "internal/suppress") {
		t.Errorf("expected no internal Go package references in the report, got:\n%s", md)
	}
}

// TestRenderMarkdown_CheckDetailIsATable and its Confluence counterpart
// guard the Category/CIS/Remediation redesign: a bullet-list ("* *X:*
// value") read as unpolished for an enterprise security report — replaced
// with a compact key-value table, per direct feedback.
func TestRenderMarkdown_CheckDetailIsATable(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
				CIS: []string{"5.1.1"}, Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "default"},
				Message: "bad thing happened", Remediation: "fix it"},
		},
	}
	md, err := report.RenderMarkdown(r, "")
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	for _, want := range []string{"| Field | Value |", "| Category | workload-security |", "| CIS | 5.1.1 |", "| Remediation | fix it |"} {
		if !strings.Contains(md, want) {
			t.Errorf("expected %q in the check detail table, got:\n%s", want, md)
		}
	}
	if strings.Contains(md, "- **Category:**") {
		t.Errorf("expected the old bullet-list format gone, got:\n%s", md)
	}
}

func TestRenderConfluence_CheckDetailIsATable(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(),
		Target:      "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Title: "Bad thing", Severity: findings.SeverityHigh, Category: "workload-security",
				CIS: []string{"5.1.1"}, Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "default"},
				Message: "bad thing happened", Remediation: "fix it"},
		},
	}
	out, err := report.RenderConfluence(r, "")
	if err != nil {
		t.Fatalf("RenderConfluence: %v", err)
	}
	for _, want := range []string{"||Field||Value||", "|Category|workload-security|", "|CIS|5.1.1|", "|Remediation|fix it|"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the check detail table, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "* *Category:*") {
		t.Errorf("expected the old bullet-list format gone, got:\n%s", out)
	}
}

// TestRenderMarkdown_RussianTemplate_ContextAndOwnerFields is the RU
// counterpart: header table, merged "Контекст" section, no
// "суб-ресурс"-style forced translation of technical terms.
func TestRenderMarkdown_RussianTemplate_ContextAndOwnerFields(t *testing.T) {
	r := report.Result{
		GeneratedAt: time.Now(), Target: "test", Owner: "team-x", ClusterEndpoint: "https://10.0.5.2:6443",
		DetectedComponents: []thirdparty.Detection{
			{Component: thirdparty.Component{Name: "cert-manager", Category: thirdparty.CategorySystem}, LabelCount: 3},
		},
	}
	md, err := report.RenderMarkdown(r, report.RussianTemplate())
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	for _, want := range []string{"## Контекст", "### Обнаруженные компоненты", "| Ответственный | team-x |", "| API-сервер кластера | https://10.0.5.2:6443 |"} {
		if !strings.Contains(md, want) {
			t.Errorf("expected %q, got:\n%s", want, md)
		}
	}
	if strings.Contains(md, "## Область проверки") {
		t.Errorf("expected the old separate \"Область проверки\" heading gone, got:\n%s", md)
	}
}
