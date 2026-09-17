package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

func TestExclusionRuleRepo_CreateGlobalAndScoped(t *testing.T) {
	ctx := context.Background()
	cluster := newTestCluster(t)

	global, err := testStore.CreateExclusionRule(ctx, storage.ExclusionRule{
		PolicyIDs: []string{"workload.no-latest-tag"},
		Match:     storage.ExclusionMatch{Kind: "Deployment", Namespace: "kube-system"},
		Reason:    "known false positive on system components",
	})
	if err != nil {
		t.Fatalf("CreateExclusionRule (global): %v", err)
	}
	if global.ID == uuid.Nil {
		t.Error("expected a generated ID")
	}
	if global.ClusterID != nil {
		t.Errorf("ClusterID = %v, want nil for a global rule", global.ClusterID)
	}

	scoped, err := testStore.CreateExclusionRule(ctx, storage.ExclusionRule{
		ClusterID: &cluster.ID,
		PolicyIDs: []string{"*"},
		Match:     storage.ExclusionMatch{Name: "legacy-*", Labels: map[string]string{"team": "archive"}},
		Reason:    "legacy workloads pending decommission",
	})
	if err != nil {
		t.Fatalf("CreateExclusionRule (scoped): %v", err)
	}
	if scoped.ClusterID == nil || *scoped.ClusterID != cluster.ID {
		t.Errorf("ClusterID = %v, want %v", scoped.ClusterID, cluster.ID)
	}
	if scoped.Match.Name != "legacy-*" || scoped.Match.Labels["team"] != "archive" {
		t.Errorf("Match round-tripped incorrectly: %+v", scoped.Match)
	}

	// A different cluster only sees the global rule, never another
	// cluster's scoped one.
	otherCluster := newTestCluster(t)
	rulesForOther, err := testStore.ListExclusionRules(ctx, &otherCluster.ID)
	if err != nil {
		t.Fatalf("ListExclusionRules (other cluster): %v", err)
	}
	sawGlobal, sawScoped := false, false
	for _, r := range rulesForOther {
		if r.ID == global.ID {
			sawGlobal = true
		}
		if r.ID == scoped.ID {
			sawScoped = true
		}
	}
	if !sawGlobal {
		t.Error("expected the global rule to apply to every cluster")
	}
	if sawScoped {
		t.Error("a rule scoped to one cluster must not leak into another cluster's list")
	}

	// The owning cluster sees both.
	rulesForOwner, err := testStore.ListExclusionRules(ctx, &cluster.ID)
	if err != nil {
		t.Fatalf("ListExclusionRules (owning cluster): %v", err)
	}
	sawGlobal, sawScoped = false, false
	for _, r := range rulesForOwner {
		if r.ID == global.ID {
			sawGlobal = true
		}
		if r.ID == scoped.ID {
			sawScoped = true
		}
	}
	if !sawGlobal || !sawScoped {
		t.Errorf("owning cluster should see both global and its own scoped rule: global=%v scoped=%v", sawGlobal, sawScoped)
	}
}

func TestExclusionRuleRepo_Delete(t *testing.T) {
	ctx := context.Background()
	rule, err := testStore.CreateExclusionRule(ctx, storage.ExclusionRule{Reason: "temporary"})
	if err != nil {
		t.Fatalf("CreateExclusionRule: %v", err)
	}
	if err := testStore.DeleteExclusionRule(ctx, rule.ID); err != nil {
		t.Fatalf("DeleteExclusionRule: %v", err)
	}
	if err := testStore.DeleteExclusionRule(ctx, rule.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("second delete: err = %v, want storage.ErrNotFound", err)
	}
}
