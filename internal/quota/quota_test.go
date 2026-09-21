package quota_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/quota"
)

func mustResource(t *testing.T, doc string) loader.Resource {
	t.Helper()
	var m map[string]interface{}
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	return loader.Resource{Object: &unstructured.Unstructured{Object: m}, Source: "test"}
}

func policyIDs(resources []loader.Resource) map[string]int {
	out := map[string]int{}
	for _, f := range quota.Analyze(resources, "test") {
		out[f.PolicyID]++
	}
	return out
}

func namespace(name string, labels map[string]string) loader.Resource {
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name": name,
		},
	}
	if labels != nil {
		l := map[string]any{}
		for k, v := range labels {
			l[k] = v
		}
		obj["metadata"].(map[string]any)["labels"] = l
	}
	return loader.Resource{Object: &unstructured.Unstructured{Object: obj}, Source: "test"}
}

func TestNamespaceWithNeitherFlagsBoth(t *testing.T) {
	ids := policyIDs([]loader.Resource{namespace("app-team", nil)})
	if ids[quota.CheckIDNoResourceQuota] != 1 || ids[quota.CheckIDNoLimitRange] != 1 {
		t.Errorf("expected both checks to fire on a namespace with neither, got %+v", ids)
	}
}

func TestNamespaceWithBothNotFlagged(t *testing.T) {
	resources := []loader.Resource{
		namespace("app-team", nil),
		mustResource(t, `
apiVersion: v1
kind: ResourceQuota
metadata:
  name: default
  namespace: app-team
spec:
  hard:
    requests.cpu: "10"
`),
		mustResource(t, `
apiVersion: v1
kind: LimitRange
metadata:
  name: default
  namespace: app-team
spec:
  limits:
    - type: Container
`),
	}
	ids := policyIDs(resources)
	if len(ids) != 0 {
		t.Errorf("expected no findings when both exist, got %+v", ids)
	}
}

func TestNamespaceWithOnlyQuotaOnlyFlagsLimitRange(t *testing.T) {
	resources := []loader.Resource{
		namespace("app-team", nil),
		mustResource(t, `
apiVersion: v1
kind: ResourceQuota
metadata:
  name: default
  namespace: app-team
spec:
  hard:
    requests.cpu: "10"
`),
	}
	ids := policyIDs(resources)
	if ids[quota.CheckIDNoResourceQuota] != 0 {
		t.Errorf("expected no-resource-quota to NOT fire when a ResourceQuota exists, got %+v", ids)
	}
	if ids[quota.CheckIDNoLimitRange] != 1 {
		t.Errorf("expected no-limit-range to fire when no LimitRange exists, got %+v", ids)
	}
}

func TestCapsuleManagedNamespaceSkipped(t *testing.T) {
	resources := []loader.Resource{
		namespace("tenant-a-ns1", map[string]string{"capsule.clastix.io/tenant": "tenant-a"}),
	}
	ids := policyIDs(resources)
	if len(ids) != 0 {
		t.Errorf("expected Capsule-managed namespaces to be skipped (covered by the Tenant-level checks instead), got %+v", ids)
	}
}

func TestDifferentNamespacesQuotaNotCrossApplied(t *testing.T) {
	resources := []loader.Resource{
		namespace("has-quota", nil),
		namespace("no-quota", nil),
		mustResource(t, `
apiVersion: v1
kind: ResourceQuota
metadata:
  name: default
  namespace: has-quota
spec:
  hard:
    requests.cpu: "10"
`),
	}
	found := quota.Analyze(resources, "test")
	var flagged []string
	for _, f := range found {
		if f.PolicyID == quota.CheckIDNoResourceQuota {
			flagged = append(flagged, f.Resource.Name)
		}
	}
	if len(flagged) != 1 || flagged[0] != "no-quota" {
		t.Errorf("expected only 'no-quota' namespace flagged for no-resource-quota, got %v", flagged)
	}
}
