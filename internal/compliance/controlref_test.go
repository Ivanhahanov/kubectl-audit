package compliance_test

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/compliance"
)

func TestBuildControlIndex_MultipleFrameworksPreserveOrder(t *testing.T) {
	internal := &compliance.Mapping{
		ID: "internal", Title: "Internal Standard", Version: "1",
		Controls: []compliance.Control{
			{ID: "4.5.2", Title: "No floating tags", Applicable: true, PolicyIDs: []string{"workload.no-latest-tag"}},
		},
	}
	cis := &compliance.Mapping{
		ID: "cis", Title: "CIS Kubernetes Benchmark", Version: "2.0.1",
		Controls: []compliance.Control{
			{ID: "5.1.3", Title: "Wildcard use", Applicable: true, PolicyIDs: []string{"workload.no-latest-tag"}},
		},
	}

	// internal listed first: it must be primary.
	idx := compliance.BuildControlIndex([]*compliance.Mapping{internal, cis})
	refs := idx["workload.no-latest-tag"]
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d: %+v", len(refs), refs)
	}
	primary, related := compliance.SplitPrimary(refs)
	if primary != "Internal Standard: 4.5.2 — No floating tags" {
		t.Errorf("expected Internal Standard primary, got %q", primary)
	}
	if related != "CIS Kubernetes Benchmark: 5.1.3 — Wildcard use" {
		t.Errorf("expected CIS as related, got %q", related)
	}

	// cis listed first: it must be primary instead — order, not framework
	// identity, decides priority.
	idxReversed := compliance.BuildControlIndex([]*compliance.Mapping{cis, internal})
	primary2, related2 := compliance.SplitPrimary(idxReversed["workload.no-latest-tag"])
	if primary2 != "CIS Kubernetes Benchmark: 5.1.3 — Wildcard use" {
		t.Errorf("expected CIS primary when listed first, got %q", primary2)
	}
	if related2 != "Internal Standard: 4.5.2 — No floating tags" {
		t.Errorf("expected Internal Standard as related, got %q", related2)
	}
}

func TestSplitPrimary_Empty(t *testing.T) {
	primary, related := compliance.SplitPrimary(nil)
	if primary != "" || related != "" {
		t.Errorf("expected both empty for no refs, got primary=%q related=%q", primary, related)
	}
}

func TestBuildControlIndex_NativeCheckIDsAlsoIndexed(t *testing.T) {
	m := &compliance.Mapping{
		ID: "internal", Title: "Internal Standard", Version: "1",
		Controls: []compliance.Control{
			{ID: "4.2.6", Applicable: true, NativeCheckIDs: []string{"rbac-analyzer.system-masters-usage"}},
		},
	}
	idx := compliance.BuildControlIndex([]*compliance.Mapping{m})
	if len(idx["rbac-analyzer.system-masters-usage"]) != 1 {
		t.Errorf("expected native check ID to be indexed too, got %+v", idx)
	}
}
