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
