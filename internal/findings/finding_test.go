package findings_test

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

func TestNewIDDiscriminator(t *testing.T) {
	ref := findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "ns"}
	id1 := findings.NewID("policy", ref, "expr-a")
	id2 := findings.NewID("policy", ref, "expr-b")
	if id1 == id2 {
		t.Errorf("expected distinct IDs for different discriminators, both got %s", id1)
	}
	if findings.NewID("policy", ref, "expr-a") != id1 {
		t.Errorf("expected NewID to be deterministic for identical inputs")
	}
}

// TestScopeID_DifferentScopesDoNotCollide is the actual multi-cluster
// safety property: two clusters running the same GitOps-templated
// manifest (identical namespace/Deployment names) produce the same raw
// NewID — ScopeID must still tell them apart once each is scoped by its
// own cluster's Target label.
func TestScopeID_DifferentScopesDoNotCollide(t *testing.T) {
	ref := findings.ResourceRef{Kind: "Deployment", Name: "app", Namespace: "prod"}
	raw := findings.NewID("workload.x", ref)

	clusterA := findings.ScopeID(raw, "cluster:cluster-a")
	clusterB := findings.ScopeID(raw, "cluster:cluster-b")
	if clusterA == clusterB {
		t.Errorf("expected different scopes to produce different IDs, both got %s", clusterA)
	}
}

// TestScopeID_Deterministic guards the property triage state persistence
// depends on: the same (id, scope) pair must always scope to the same ID
// across separate scans of the same cluster, or every triage entry would
// look "new" on every run.
func TestScopeID_Deterministic(t *testing.T) {
	ref := findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "ns"}
	raw := findings.NewID("workload.x", ref)
	if findings.ScopeID(raw, "cluster:prod") != findings.ScopeID(raw, "cluster:prod") {
		t.Error("expected ScopeID to be deterministic for identical inputs")
	}
}

// TestScopeFindingIDs_RewritesEveryFindingInPlace guards the actual call
// site's contract (internal/cli's runScan/rbac_analyze): every finding in
// the slice gets its ID rewritten in place, and two findings that shared
// an ID before scoping still share one after (Dedupe, which runs
// immediately after scoping, depends on this).
func TestScopeFindingIDs_RewritesEveryFindingInPlace(t *testing.T) {
	ref := findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "ns"}
	rawID := findings.NewID("workload.x", ref)
	fs := []findings.Finding{
		{ID: rawID, PolicyID: "workload.x"},
		{ID: rawID, PolicyID: "workload.x"}, // duplicate, same as Dedupe would see pre-scoping
	}
	findings.ScopeFindingIDs(fs, "cluster:prod")

	if fs[0].ID == rawID {
		t.Errorf("expected the ID rewritten in place, still got the raw unscoped ID %s", rawID)
	}
	if fs[0].ID != fs[1].ID {
		t.Errorf("expected findings sharing a pre-scoping ID to still share one after scoping, got %s vs %s", fs[0].ID, fs[1].ID)
	}
}

func TestDedupeKeepsDistinctDiscriminators(t *testing.T) {
	ref := findings.ResourceRef{Kind: "Pod", Name: "p"}
	in := []findings.Finding{
		{ID: findings.NewID("p", ref, "a"), PolicyID: "p"},
		{ID: findings.NewID("p", ref, "b"), PolicyID: "p"},
		{ID: findings.NewID("p", ref, "a"), PolicyID: "p"}, // duplicate of the first
	}
	out := findings.Dedupe(in)
	if len(out) != 2 {
		t.Errorf("expected 2 unique findings after dedupe, got %d", len(out))
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !findings.SeverityHigh.AtLeast(findings.SeverityMedium) {
		t.Error("HIGH should be AtLeast MEDIUM")
	}
	if findings.SeverityLow.AtLeast(findings.SeverityHigh) {
		t.Error("LOW should not be AtLeast HIGH")
	}
	if !findings.SeverityCritical.AtLeast(findings.SeverityCritical) {
		t.Error("a severity should be AtLeast itself")
	}
}

func TestParseSeverityCaseInsensitive(t *testing.T) {
	if findings.ParseSeverity("High") != findings.SeverityHigh {
		t.Error("expected case-insensitive parsing")
	}
	if findings.ParseSeverity("bogus") != findings.SeverityMedium {
		t.Error("expected unrecognized severity to default to MEDIUM")
	}
}
