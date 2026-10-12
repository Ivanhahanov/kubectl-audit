package kyverno_test

import (
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/ivanhahanov/kubectl-audit/internal/engine"
	"github.com/ivanhahanov/kubectl-audit/internal/kyverno"
)

func loadFixture(t *testing.T) *engine.CompiledPolicy {
	t.Helper()
	policies, err := engine.LoadDir("../../examples/custom-policy-example.yaml")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected exactly 1 policy, got %d", len(policies))
	}
	return policies[0]
}

func TestToValidatingPolicy_CopiesMatchConstraintsAndValidations(t *testing.T) {
	cp := loadFixture(t)
	doc := kyverno.ToValidatingPolicy(cp)

	if doc["apiVersion"] != "policies.kyverno.io/v1" {
		t.Errorf("apiVersion = %v", doc["apiVersion"])
	}
	if doc["kind"] != "ValidatingPolicy" {
		t.Errorf("kind = %v", doc["kind"])
	}
	spec := doc["spec"].(map[string]any)
	if spec["matchConstraints"] != cp.Policy.Spec.MatchConstraints {
		t.Errorf("matchConstraints should be a direct copy of the source VAP's pointer/value, not rebuilt")
	}
	if len(spec["validations"].([]admissionregistrationv1.Validation)) != len(cp.Policy.Spec.Validations) {
		t.Errorf("validations should be a direct copy of the source VAP's")
	}
}

func TestToClusterPolicy_ResolvesViaStaticKindTable(t *testing.T) {
	cp := loadFixture(t) // targets apps/{deployments,statefulsets,daemonsets}
	doc, unresolved := kyverno.ToClusterPolicy(cp, kyverno.StaticKindResolver)
	if len(unresolved) != 0 {
		t.Fatalf("expected no unresolved resources, got %v", unresolved)
	}
	if doc["kind"] != "ClusterPolicy" {
		t.Errorf("kind = %v", doc["kind"])
	}
	rules := doc["spec"].(map[string]any)["rules"].([]map[string]any)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	anyMatches := rules[0]["match"].(map[string]any)["any"].([]map[string]any)
	if len(anyMatches) != 1 {
		t.Fatalf("expected 1 match.any entry (1 source resourceRule), got %d", len(anyMatches))
	}
	kinds := anyMatches[0]["resources"].(map[string]any)["kinds"].([]string)
	want := map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true}
	if len(kinds) != len(want) {
		t.Fatalf("got kinds %v, want %v", kinds, want)
	}
	for _, k := range kinds {
		if !want[k] {
			t.Errorf("unexpected kind %q in %v", k, kinds)
		}
	}
}

func TestToClusterPolicy_UnresolvedResourceIsReportedNotGuessed(t *testing.T) {
	cp := loadFixture(t)
	alwaysFail := func(schema.GroupVersionResource) (string, bool) { return "", false }
	doc, unresolved := kyverno.ToClusterPolicy(cp, alwaysFail)
	if doc != nil {
		t.Errorf("expected nil doc when resources can't be resolved, got %v", doc)
	}
	if len(unresolved) != 3 {
		t.Fatalf("expected 3 unresolved resources (deployments/statefulsets/daemonsets), got %v", unresolved)
	}
}

func TestChainKindResolvers_FallsThroughToSecondResolver(t *testing.T) {
	alwaysFail := func(schema.GroupVersionResource) (string, bool) { return "", false }
	chained := kyverno.ChainKindResolvers(alwaysFail, kyverno.StaticKindResolver)
	kind, ok := chained(schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"})
	if !ok || kind != "Deployment" {
		t.Errorf("got (%q, %v), want (\"Deployment\", true)", kind, ok)
	}
}

func TestUnresolvedKindError_NamesThePolicyAndResources(t *testing.T) {
	err := kyverno.UnresolvedKindError("org.require-owner-label", []string{"example.com/widgets"})
	if err == nil {
		t.Fatal("expected a non-nil error")
	}
	msg := err.Error()
	if !contains(msg, "org.require-owner-label") || !contains(msg, "example.com/widgets") {
		t.Errorf("error message %q should name both the policy and the unresolved resource", msg)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
