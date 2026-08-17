package thirdparty_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/thirdparty"
)

func resourceOf(apiVersion, kind, name string, labels map[string]any) loader.Resource {
	obj := map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata":   map[string]any{"name": name},
	}
	if labels != nil {
		obj["metadata"].(map[string]any)["labels"] = labels
	}
	return loader.Resource{Object: &unstructured.Unstructured{Object: obj}}
}

func TestDetect_FindsKnownComponentsWithCounts(t *testing.T) {
	resources := []loader.Resource{
		resourceOf("cilium.io/v2", "CiliumNetworkPolicy", "np1", nil),
		resourceOf("cilium.io/v2", "CiliumNetworkPolicy", "np2", nil),
		resourceOf("capsule.clastix.io/v1beta2", "Tenant", "t1",
			map[string]any{"app.kubernetes.io/managed-by": "Helm"}),
		resourceOf("apps/v1", "Deployment", "d1", nil), // unrelated, shouldn't match anything
	}
	got := thirdparty.Detect(resources, thirdparty.Known)

	byName := map[string]thirdparty.Detection{}
	for _, d := range got {
		byName[d.Name] = d
	}
	if len(got) != 2 {
		t.Fatalf("expected exactly 2 detected components, got %+v", got)
	}
	if cilium := byName["Cilium"]; cilium.GroupCount != 2 || cilium.HelmManaged {
		t.Errorf("expected Cilium: groupCount=2, helmManaged=false, got %+v", cilium)
	}
	if capsule := byName["Capsule"]; capsule.GroupCount != 1 || !capsule.HelmManaged {
		t.Errorf("expected Capsule: groupCount=1, helmManaged=true, got %+v", capsule)
	}
}

func TestDetect_Mismatched(t *testing.T) {
	// Cilium's CRD is present but no workload carries k8s-app: cilium —
	// the built-in exception isn't suppressing anything for this cluster.
	resources := []loader.Resource{
		resourceOf("cilium.io/v2", "CiliumNetworkPolicy", "np1", nil),
	}
	got := thirdparty.Detect(resources, thirdparty.Known)
	if len(got) != 1 || !got[0].Mismatched() {
		t.Fatalf("expected Cilium detected with Mismatched()==true, got %+v", got)
	}

	// Once the agent label is present too, it's no longer mismatched.
	resources = append(resources, resourceOf("apps/v1", "DaemonSet", "cilium",
		map[string]any{"k8s-app": "cilium"}))
	got = thirdparty.Detect(resources, thirdparty.Known)
	if len(got) != 1 || got[0].Mismatched() {
		t.Fatalf("expected Mismatched()==false once the agent label is found, got %+v", got)
	}
}

func TestDetect_MismatchedAppliesToApplicationCategoryToo(t *testing.T) {
	// Orphaned CRDs are not a System-only concern: `helm uninstall` leaves
	// CRDs (and any CRs) behind by default for Application components too,
	// so the same "CRD group present, no matching operator workload"
	// signal needs to fire regardless of category.
	resources := []loader.Resource{
		resourceOf("postgresql.cnpg.io/v1", "Cluster", "pg1", nil),
	}
	got := thirdparty.Detect(resources, thirdparty.Known)
	if len(got) != 1 || got[0].Category != thirdparty.CategoryApplication || !got[0].Mismatched() {
		t.Fatalf("expected CloudNativePG detected as Application with Mismatched()==true, got %+v", got)
	}

	resources = append(resources, resourceOf("apps/v1", "Deployment", "cnpg-controller-manager",
		map[string]any{"app.kubernetes.io/name": "cloudnative-pg"}))
	got = thirdparty.Detect(resources, thirdparty.Known)
	if len(got) != 1 || got[0].Mismatched() {
		t.Fatalf("expected Mismatched()==false once the operator Deployment is found, got %+v", got)
	}
}

func TestDetect_NoneFound(t *testing.T) {
	resources := []loader.Resource{resourceOf("apps/v1", "Deployment", "d1", nil)}
	if got := thirdparty.Detect(resources, thirdparty.Known); len(got) != 0 {
		t.Errorf("expected no components detected, got %v", got)
	}
}
