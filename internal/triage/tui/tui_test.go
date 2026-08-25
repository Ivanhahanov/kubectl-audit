package tui

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

func findingWith(id string, ns, name string) findings.Finding {
	return findingWithPolicy(id, "workload.no-latest-tag", "m", ns, name)
}

func findingWithPolicy(id, policyID, message, ns, name string) findings.Finding {
	return findings.Finding{
		ID: id, PolicyID: policyID, Title: "t", Severity: findings.SeverityLow,
		Category: "supply-chain", Resource: findings.ResourceRef{Kind: "Deployment", Namespace: ns, Name: name},
		Message: message,
	}
}

func newTestApp(all []findings.Finding) *app {
	return &app{
		all:      all,
		state:    &triage.State{Entries: map[string]triage.Entry{}},
		marked:   map[string]bool{},
		collapse: true,
	}
}

// TestRefresh_DefaultCollapseHidesDuplicates exercises refresh() (the pure
// row-computation path, no tview widgets touched): with collapse on
// (default) and a threshold met, 3 near-identical findings across 3 tenant
// namespaces should show as a single representative row, with
// dedupMembers recording all 3.
func TestRefresh_DefaultCollapseHidesDuplicates(t *testing.T) {
	all := []findings.Finding{
		findingWith("a", "tenant-a", "app"),
		findingWith("b", "tenant-b", "app"),
		findingWith("c", "tenant-c", "app"),
	}
	a := newTestApp(all)
	a.dedupThreshold = 3
	a.refresh()

	if len(a.rows) != 1 {
		t.Fatalf("expected the 3 near-duplicate findings to collapse to 1 row, got %d", len(a.rows))
	}
	members := a.dedupMembers[a.rows[0].Entry.FindingID]
	if len(members) != 3 {
		t.Errorf("expected the representative row's dedup bucket to hold all 3 members, got %d", len(members))
	}
}

// TestRefresh_ExpandGroupDrillsIntoCollapsedBucket verifies 'g' (expandGroup)
// shows the individual members of one collapsed bucket instead of its
// representative row, without disturbing collapse elsewhere.
func TestRefresh_ExpandGroupDrillsIntoCollapsedBucket(t *testing.T) {
	all := []findings.Finding{
		findingWith("a", "tenant-a", "app"),
		findingWith("b", "tenant-b", "app"),
		findingWith("c", "tenant-c", "app"),
	}
	a := newTestApp(all)
	a.dedupThreshold = 3
	a.refresh()
	if len(a.rows) != 1 {
		t.Fatalf("setup: expected 1 collapsed row, got %d", len(a.rows))
	}

	a.expandGroup = dedupKey(a.rows[0])
	a.refresh()
	if len(a.rows) != 3 {
		t.Fatalf("expected expandGroup to reveal all 3 individual members, got %d", len(a.rows))
	}

	a.expandGroup = ""
	a.refresh()
	if len(a.rows) != 1 {
		t.Fatalf("expected clearing expandGroup to re-collapse back to 1 row, got %d", len(a.rows))
	}
}

// TestRefresh_SystemFilterIsolatesNamespaceAcrossPolicies verifies 's'
// (systemFilter) shows every finding in one namespace regardless of which
// policy/Kind flagged it, and excludes every other namespace — the
// "investigate this tenant end-to-end" view, distinct from dedup
// collapsing (which is scoped to a single policy).
func TestRefresh_SystemFilterIsolatesNamespaceAcrossPolicies(t *testing.T) {
	all := []findings.Finding{
		findingWithPolicy("a", "policy.one", "msg-1", "tenant-a", "app"),
		findingWithPolicy("b", "policy.two", "msg-2", "tenant-a", "worker"),
		findingWithPolicy("c", "policy.one", "msg-1", "tenant-b", "app"),
	}
	a := newTestApp(all)
	a.dedupThreshold = 3
	a.systemFilter = "tenant-a"
	a.refresh()

	if len(a.rows) != 2 {
		t.Fatalf("expected 2 rows isolated to tenant-a across both policies, got %d", len(a.rows))
	}
	for _, r := range a.rows {
		if r.Entry.Resource.Namespace != "tenant-a" {
			t.Errorf("row %s has namespace %q, want tenant-a", r.Entry.FindingID, r.Entry.Resource.Namespace)
		}
	}
}
