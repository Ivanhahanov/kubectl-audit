package tui

import (
	"fmt"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

func dedupRow(id, policyID, message, ns, name string) triage.Row {
	f := findings.Finding{
		ID: id, PolicyID: policyID, Title: "t", Severity: findings.SeverityLow,
		Category: "supply-chain", Resource: findings.ResourceRef{Kind: "Deployment", Namespace: ns, Name: name},
		Message: message,
	}
	return triage.Row{
		Finding:  &f,
		Entry:    triage.Entry{FindingID: id, PolicyID: f.PolicyID, Resource: f.Resource, Title: f.Title},
		GroupKey: triage.GroupKey(f.Resource),
	}
}

func dedupRowWithKey(id, policyID, message, dedupKey, ns, name string) triage.Row {
	r := dedupRow(id, policyID, message, ns, name)
	r.Finding.DedupKey = dedupKey
	return r
}

func TestDedupGroups_DifferentPoliciesNeverCollapseTogether(t *testing.T) {
	rows := []triage.Row{
		dedupRow("1", "policy.a", "msg-a", "tenant-1", "app"),
		dedupRow("2", "policy.a", "msg-a", "tenant-2", "app"),
		dedupRow("3", "policy.a", "msg-a", "tenant-3", "app"),
		dedupRow("4", "policy.b", "msg-b", "tenant-1", "app"),
		dedupRow("5", "policy.b", "msg-b", "tenant-2", "app"),
		dedupRow("6", "policy.b", "msg-b", "tenant-3", "app"),
	}
	result, members := dedupGroups(rows, 3)
	if len(result) != 2 {
		t.Fatalf("expected 2 representative rows (one per policy), got %d: %+v", len(result), result)
	}
	total := 0
	for _, m := range members {
		total += len(m)
	}
	if total != 6 {
		t.Errorf("expected all 6 original rows accounted for across both buckets, got %d", total)
	}
}

// TestDedupGroups_NonUniformMessagePolicyNeverCollapses: 3 findings under
// one policy with 3 substantively different messages land in 3 separate
// dedupKey buckets (PolicyID+Kind+normalizedMessage) — each bucket has only
// 1 member, below threshold 3, so none collapse. No resource-specific
// detail is ever hidden.
func TestDedupGroups_NonUniformMessagePolicyNeverCollapses(t *testing.T) {
	rows := []triage.Row{
		dedupRow("1", "rbac.least-privilege", "role X grants get on secrets", "ns", "a"),
		dedupRow("2", "rbac.least-privilege", "role Y grants list on pods", "ns", "b"),
		dedupRow("3", "rbac.least-privilege", "role Z grants delete on nodes", "ns", "c"),
	}
	result, members := dedupGroups(rows, 3)
	if len(result) != 3 {
		t.Errorf("expected no collapsing for a policy with per-resource messages, got %d rows", len(result))
	}
	if len(members) != 0 {
		t.Errorf("expected no dedup members recorded, got %d", len(members))
	}
}

// TestDedupGroups_OutlierMessageDoesNotBlockOtherRowsFromCollapsing is the
// regression test for a real bug found on a real cluster: the previous
// design gated collapsing on a per-PolicyID "are ALL of this policy's
// messages identical" check — one finding with a genuinely different
// message (e.g. a Group subject alongside many ServiceAccount ones) tripped
// that gate for the ENTIRE policy, so none of its findings collapsed
// anywhere, not just the outlier. Bucketing directly on
// PolicyID+Kind+normalizedMessage fixes this: the 3 identical findings
// still collapse into 1 representative, and the outlier just stays its own
// separate row — it no longer blocks the rest of the policy.
func TestDedupGroups_OutlierMessageDoesNotBlockOtherRowsFromCollapsing(t *testing.T) {
	msg := func(ns string) string {
		return `ServiceAccount "checker-sa" in namespace "` + ns + `" can read Secrets cluster-wide, via: ClusterRoleBinding "checker-sa-binding-` + ns + `".`
	}
	rows := []triage.Row{
		dedupRow("1", "rbac-analyzer.broad-secrets-access", msg("pg-cl-aaa"), "pg-cl-aaa", "checker-sa"),
		dedupRow("2", "rbac-analyzer.broad-secrets-access", msg("pg-cl-bbb"), "pg-cl-bbb", "checker-sa"),
		dedupRow("3", "rbac-analyzer.broad-secrets-access", msg("pg-cl-ccc"), "pg-cl-ccc", "checker-sa"),
		dedupRow("4", "rbac-analyzer.broad-secrets-access",
			`Group "kubeadm:cluster-admins" can read Secrets cluster-wide, via: ClusterRoleBinding "kubeadm:cluster-admins" -> ClusterRole "cluster-admin".`,
			"", "kubeadm:cluster-admins"),
	}
	result, members := dedupGroups(rows, 3)
	if len(result) != 2 {
		t.Fatalf("expected 2 rows: 1 collapsed representative for the 3 identical tenants + 1 for the outlier, got %d: %+v", len(result), result)
	}
	total := 0
	for _, m := range members {
		total += len(m)
	}
	if total != 3 {
		t.Errorf("expected exactly the 3 identical findings recorded as collapsed members, got %d", total)
	}
}

func TestDedupGroups_ThresholdBoundary(t *testing.T) {
	twoRows := []triage.Row{
		dedupRow("1", "policy.a", "msg", "tenant-1", "app"),
		dedupRow("2", "policy.a", "msg", "tenant-2", "app"),
	}
	if result, _ := dedupGroups(twoRows, 3); len(result) != 2 {
		t.Errorf("expected 2 rows below threshold to stay uncollapsed, got %d", len(result))
	}

	threeRows := []triage.Row{
		dedupRow("1", "policy.a", "msg", "tenant-1", "app"),
		dedupRow("2", "policy.a", "msg", "tenant-2", "app"),
		dedupRow("3", "policy.a", "msg", "tenant-3", "app"),
	}
	result, members := dedupGroups(threeRows, 3)
	if len(result) != 1 {
		t.Fatalf("expected exactly-at-threshold rows to collapse to 1, got %d", len(result))
	}
	if len(members[result[0].Entry.FindingID]) != 3 {
		t.Errorf("expected the representative's member list to contain all 3, got %d", len(members[result[0].Entry.FindingID]))
	}
}

func TestDedupGroups_ResolvedRowsNeverCollapse(t *testing.T) {
	resolved := dedupRow("1", "policy.a", "msg", "tenant-1", "app")
	resolved.Finding = nil
	resolved.Entry.Status = triage.StatusResolved
	rows := []triage.Row{
		resolved,
		dedupRow("2", "policy.a", "msg", "tenant-2", "app"),
		dedupRow("3", "policy.a", "msg", "tenant-3", "app"),
	}
	result, _ := dedupGroups(rows, 3)
	// Only 2 live findings share the bucket — below threshold 3, so nothing
	// collapses; the resolved row passes through untouched either way.
	if len(result) != 3 {
		t.Errorf("expected 3 rows (resolved row never collapses, live ones below threshold), got %d", len(result))
	}
}

func TestDedupGroups_ZeroThresholdDisablesCollapsing(t *testing.T) {
	rows := []triage.Row{
		dedupRow("1", "policy.a", "msg", "tenant-1", "app"),
		dedupRow("2", "policy.a", "msg", "tenant-2", "app"),
		dedupRow("3", "policy.a", "msg", "tenant-3", "app"),
	}
	result, members := dedupGroups(rows, 0)
	if len(result) != 3 {
		t.Errorf("expected threshold<=0 to disable collapsing entirely, got %d rows", len(result))
	}
	if len(members) != 0 {
		t.Errorf("expected no members map entries when collapsing is disabled, got %d", len(members))
	}
}

// TestDedupGroups_CollapsesTemplatedPerTenantResourceMessages is the fix for
// a real report: rbac-analyzer.broad-secrets-access fires once per
// generated per-tenant namespace ("pg-cl-<uuid>") for the same
// ServiceAccount name ("checker-sa") via the same generated binding
// pattern — the message embeds that namespace/name so it was never
// literally identical across tenants without normalization, even though
// it's mechanically the same finding repeated. normalizedMessage strips
// each finding's own resource identity before bucketing so this collapses.
func TestDedupGroups_CollapsesTemplatedPerTenantResourceMessages(t *testing.T) {
	msg := func(ns string) string {
		return `ServiceAccount "checker-sa" in namespace "` + ns + `" can read Secrets cluster-wide, via: ClusterRoleBinding "checker-sa-binding-` + ns + `" -> ClusterRole "checker-role".`
	}
	rows := []triage.Row{
		dedupRow("1", "rbac-analyzer.broad-secrets-access", msg("pg-cl-aaa"), "pg-cl-aaa", "checker-sa"),
		dedupRow("2", "rbac-analyzer.broad-secrets-access", msg("pg-cl-bbb"), "pg-cl-bbb", "checker-sa"),
		dedupRow("3", "rbac-analyzer.broad-secrets-access", msg("pg-cl-ccc"), "pg-cl-ccc", "checker-sa"),
	}
	result, members := dedupGroups(rows, 3)
	if len(result) != 1 {
		t.Fatalf("expected the 3 per-tenant findings to collapse to 1 representative, got %d: %+v", len(result), result)
	}
	if len(members[result[0].Entry.FindingID]) != 3 {
		t.Errorf("expected the representative's member list to contain all 3, got %d", len(members[result[0].Entry.FindingID]))
	}
}

// TestDedupGroups_SubstantiveMessageDifferenceStillBlocksCollapse guards
// against normalizedMessage over-collapsing: two findings on differently
// named/namespaced resources whose messages ALSO differ in substance (a
// different reachable secret set, not just the resource's own identity)
// must still be treated as non-uniform.
func TestDedupGroups_SubstantiveMessageDifferenceStillBlocksCollapse(t *testing.T) {
	rows := []triage.Row{
		dedupRow("1", "rbac-analyzer.broad-secrets-access", `ServiceAccount "sa" in namespace "ns-a" can read Secrets across 2 namespaces, via: RoleBinding "ns-a/rb".`, "ns-a", "sa"),
		dedupRow("2", "rbac-analyzer.broad-secrets-access", `ServiceAccount "sa" in namespace "ns-b" can read Secrets cluster-wide, via: ClusterRoleBinding "crb".`, "ns-b", "sa"),
		dedupRow("3", "rbac-analyzer.broad-secrets-access", `ServiceAccount "sa" in namespace "ns-c" can read Secrets across 5 namespaces, via: RoleBinding "ns-c/rb2".`, "ns-c", "sa"),
	}
	result, members := dedupGroups(rows, 3)
	if len(result) != 3 {
		t.Errorf("expected findings with substantively different messages to stay uncollapsed, got %d rows: %+v", len(result), result)
	}
	if len(members) != 0 {
		t.Errorf("expected no dedup members recorded, got %d", len(members))
	}
}

// TestDedupGroups_CollapsesAtRealClusterScale confirms both correctness and
// the switch away from regexp.MustCompile-per-row hold at the scale this
// was actually reported broken at: a multi-tenant cluster with thousands of
// near-identical per-tenant findings (mirroring the real pg-cl-<uuid>/
// checker-sa shape).
func TestDedupGroups_CollapsesAtRealClusterScale(t *testing.T) {
	const n = 2000
	rows := make([]triage.Row, n)
	for i := 0; i < n; i++ {
		ns := fmt.Sprintf("pg-cl-%08x", i)
		msg := `ServiceAccount "checker-sa" in namespace "` + ns + `" can read Secrets cluster-wide, via: ClusterRoleBinding "checker-sa-binding-` + ns + `".`
		rows[i] = dedupRow(fmt.Sprintf("f%d", i), "rbac-analyzer.broad-secrets-access", msg, ns, "checker-sa")
	}
	result, members := dedupGroups(rows, 3)
	if len(result) != 1 {
		t.Fatalf("expected all %d per-tenant findings to collapse to 1 representative, got %d rows", n, len(result))
	}
	if len(members[result[0].Entry.FindingID]) != n {
		t.Errorf("expected the representative's member list to contain all %d findings, got %d", n, len(members[result[0].Entry.FindingID]))
	}
}

// TestDedupGroups_DedupKeyOverridesMessageForBucketing is the fix for a
// real report: pss-analyzer.restricted's Message names the specific
// violating container ("... (container api-v2)" vs "... (container
// app-no-ssh-here)"), which differs per tenant workload even though the
// resource's own namespace/name were already normalized away — every one
// of them stayed a separate row. An analyzer can set Finding.DedupKey to a
// coarser value (here: just the violated rule names, no container detail)
// to opt the check into bulk-triage collapsing without losing the
// per-container detail from Message itself.
func TestDedupGroups_DedupKeyOverridesMessageForBucketing(t *testing.T) {
	rows := []triage.Row{
		dedupRowWithKey("1", "pss-analyzer.restricted",
			`Does not satisfy the Pod Security Standards "restricted" profile: runAsNonRoot != true (container api-v2)`,
			"pss-analyzer.restricted|runAsNonRoot != true", "usersvs-aaa", "api-v2-00001-deployment"),
		dedupRowWithKey("2", "pss-analyzer.restricted",
			`Does not satisfy the Pod Security Standards "restricted" profile: runAsNonRoot != true (container app-no-ssh-here)`,
			"pss-analyzer.restricted|runAsNonRoot != true", "usersvs-bbb", "app-no-ssh-here-00001-deployment"),
		dedupRowWithKey("3", "pss-analyzer.restricted",
			`Does not satisfy the Pod Security Standards "restricted" profile: runAsNonRoot != true (container app-uptime-kuma)`,
			"pss-analyzer.restricted|runAsNonRoot != true", "usersvs-ccc", "app-uptime-kuma-00002-deployment"),
		// A different violated rule set must NOT join the same bucket, even
		// with the same PolicyID+Kind.
		dedupRowWithKey("4", "pss-analyzer.restricted",
			`Does not satisfy the Pod Security Standards "restricted" profile: privileged containers (container sidecar)`,
			"pss-analyzer.restricted|privileged containers", "usersvs-ddd", "other-app-00001-deployment"),
	}
	result, members := dedupGroups(rows, 3)
	if len(result) != 2 {
		t.Fatalf("expected 2 rows: 1 collapsed representative for the 3 matching-DedupKey findings + 1 for the different rule, got %d: %+v", len(result), result)
	}
	total := 0
	for _, m := range members {
		total += len(m)
	}
	if total != 3 {
		t.Errorf("expected exactly the 3 same-DedupKey findings recorded as collapsed members, got %d", total)
	}
}
