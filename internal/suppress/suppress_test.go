package suppress_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/ivanhahanov/kubectl-audit/internal/config"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/suppress"
)

func finding(policyID, kind, ns, name string) findings.Finding {
	return findings.Finding{
		PolicyID: policyID,
		Resource: findings.ResourceRef{Kind: kind, Namespace: ns, Name: name},
	}
}

func TestApply_NoRules(t *testing.T) {
	all := []findings.Finding{finding("workload.x", "Deployment", "default", "app")}
	kept, suppressed := suppress.Apply(all, nil, nil)
	if len(kept) != 1 || len(suppressed) != 0 {
		t.Fatalf("expected passthrough with no rules, got kept=%d suppressed=%d", len(kept), len(suppressed))
	}
}

func TestApply_MatchByNameGlob(t *testing.T) {
	all := []findings.Finding{
		finding("workload.no-latest-tag", "Deployment", "default", "legacy-app"),
		finding("workload.no-latest-tag", "Deployment", "default", "other-app"),
	}
	rules := []config.ExclusionRule{
		{Match: config.ExclusionMatch{Name: "legacy-*"}, Reason: "legacy, JIRA-1234"},
	}
	kept, suppressed := suppress.Apply(all, rules, nil)
	if len(kept) != 1 || kept[0].Resource.Name != "other-app" {
		t.Fatalf("expected only other-app kept, got %+v", kept)
	}
	if len(suppressed) != 1 || suppressed[0].Reason != "legacy, JIRA-1234" {
		t.Fatalf("expected legacy-app suppressed with reason, got %+v", suppressed)
	}
}

func TestApply_PolicyIDScoped(t *testing.T) {
	all := []findings.Finding{
		finding("workload.no-latest-tag", "Deployment", "default", "app"),
		finding("workload.no-privileged-containers", "Deployment", "default", "app"),
	}
	rules := []config.ExclusionRule{
		{PolicyIDs: []string{"workload.no-latest-tag"}, Match: config.ExclusionMatch{Name: "app"}, Reason: "r"},
	}
	kept, suppressed := suppress.Apply(all, rules, nil)
	if len(kept) != 1 || kept[0].PolicyID != "workload.no-privileged-containers" {
		t.Fatalf("expected only the non-matching policy kept, got %+v", kept)
	}
	if len(suppressed) != 1 {
		t.Fatalf("expected exactly one suppressed, got %d", len(suppressed))
	}
}

func TestApply_MatchByLabels(t *testing.T) {
	res := loader.Resource{Object: &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name": "app", "namespace": "default",
			"labels": map[string]any{"app.kubernetes.io/managed-by": "helm-operator"},
		},
	}}}
	idx := suppress.BuildLabelIndex([]loader.Resource{res})

	all := []findings.Finding{finding("workload.x", "Deployment", "default", "app")}
	rules := []config.ExclusionRule{
		{Match: config.ExclusionMatch{Labels: map[string]string{"app.kubernetes.io/managed-by": "helm-operator"}}, Reason: "r"},
	}
	kept, suppressed := suppress.Apply(all, rules, idx)
	if len(kept) != 0 || len(suppressed) != 1 {
		t.Fatalf("expected the labeled resource suppressed, got kept=%d suppressed=%d", len(kept), len(suppressed))
	}

	// A resource with no indexed labels (e.g. an RBAC Group/User subject)
	// must never match a Labels rule.
	unindexed := []findings.Finding{finding("workload.x", "Group", "", "system:masters")}
	kept2, suppressed2 := suppress.Apply(unindexed, rules, idx)
	if len(kept2) != 1 || len(suppressed2) != 0 {
		t.Fatalf("expected an unindexed resource to never match a labels rule, got kept=%d suppressed=%d", len(kept2), len(suppressed2))
	}
}
