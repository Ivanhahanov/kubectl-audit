package istio_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/ivanhahanov/kubectl-audit/internal/istio"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

func mustResource(t *testing.T, doc string) loader.Resource {
	t.Helper()
	var m map[string]interface{}
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	return loader.Resource{Object: &unstructured.Unstructured{Object: m}, Source: "test"}
}

func namespace(name string, labels map[string]string) loader.Resource {
	l := map[string]any{}
	for k, v := range labels {
		l[k] = v
	}
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name":   name,
			"labels": l,
		},
	}
	return loader.Resource{Object: &unstructured.Unstructured{Object: obj}, Source: "test"}
}

func policyIDs(t *testing.T, resources []loader.Resource) map[string]int {
	t.Helper()
	found, err := istio.AnalyzeAuthorizationCoverage(resources, "test")
	if err != nil {
		t.Fatalf("AnalyzeAuthorizationCoverage: %v", err)
	}
	out := map[string]int{}
	for _, f := range found {
		out[f.PolicyID]++
	}
	return out
}

func meshPod() loader.Resource {
	return loader.Resource{Object: &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "app",
			"namespace": "payments",
			"labels":    map[string]any{"app": "app"},
		},
		"spec": map[string]any{"containers": []any{map[string]any{"name": "c", "image": "nginx"}}},
	}}, Source: "test"}
}

func TestMeshNamespaceNoPolicyFlagged(t *testing.T) {
	resources := []loader.Resource{
		namespace("payments", map[string]string{"istio-injection": "enabled"}),
		meshPod(),
	}
	ids := policyIDs(t, resources)
	if ids[istio.CheckID] != 1 {
		t.Errorf("expected no-authorization-policy-coverage to fire in a mesh namespace with zero policies, got %+v", ids)
	}
}

func TestNonMeshNamespaceNotFlagged(t *testing.T) {
	resources := []loader.Resource{
		namespace("payments", nil),
		meshPod(),
	}
	ids := policyIDs(t, resources)
	if len(ids) != 0 {
		t.Errorf("expected no finding for a namespace without istio-injection/istio.io/rev, got %+v", ids)
	}
}

func TestRevisionedInjectionLabelAlsoCounts(t *testing.T) {
	resources := []loader.Resource{
		namespace("payments", map[string]string{"istio.io/rev": "1-24-1"}),
		meshPod(),
	}
	ids := policyIDs(t, resources)
	if ids[istio.CheckID] != 1 {
		t.Errorf("expected istio.io/rev to also count as mesh-enabled, got %+v", ids)
	}
}

func TestNamespaceWideAllowPolicyCoversWorkload(t *testing.T) {
	resources := []loader.Resource{
		namespace("payments", map[string]string{"istio-injection": "enabled"}),
		meshPod(),
		mustResource(t, `
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: default
  namespace: payments
spec:
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/frontend/sa/web"]
`),
	}
	ids := policyIDs(t, resources)
	if len(ids) != 0 {
		t.Errorf("expected a namespace-wide (empty selector) ALLOW policy to cover the workload, got %+v", ids)
	}
}

func TestWorkloadScopedAllowPolicyCoversMatchingWorkload(t *testing.T) {
	resources := []loader.Resource{
		namespace("payments", map[string]string{"istio-injection": "enabled"}),
		meshPod(),
		mustResource(t, `
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: scoped
  namespace: payments
spec:
  selector:
    matchLabels: {app: app}
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/frontend/sa/web"]
`),
	}
	ids := policyIDs(t, resources)
	if len(ids) != 0 {
		t.Errorf("expected a matching workload-scoped ALLOW policy to cover the workload, got %+v", ids)
	}
}

func TestNonMatchingSelectorStillFlagged(t *testing.T) {
	resources := []loader.Resource{
		namespace("payments", map[string]string{"istio-injection": "enabled"}),
		meshPod(),
		mustResource(t, `
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: scoped
  namespace: payments
spec:
  selector:
    matchLabels: {app: other}
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/frontend/sa/web"]
`),
	}
	ids := policyIDs(t, resources)
	if ids[istio.CheckID] != 1 {
		t.Errorf("expected the workload to still be flagged when the only ALLOW policy selects a different workload, got %+v", ids)
	}
}

func TestDenyOnlyPolicyDoesNotCount(t *testing.T) {
	resources := []loader.Resource{
		namespace("payments", map[string]string{"istio-injection": "enabled"}),
		meshPod(),
		mustResource(t, `
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: deny-admin
  namespace: payments
spec:
  action: DENY
  rules:
    - to:
        - operation:
            paths: ["/admin/*"]
`),
	}
	ids := policyIDs(t, resources)
	if ids[istio.CheckID] != 1 {
		t.Errorf("expected a DENY-only policy to NOT count as coverage (Istio's allow-all default persists), got %+v", ids)
	}
}
