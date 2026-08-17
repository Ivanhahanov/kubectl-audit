package engine_test

// TestBuiltinPolicyResourcesResolveToARegisteredKind guards against a
// previously-real bug class: engine.Matches resolves a loaded object's Kind
// to a plural resource name via internal/loader.ResourceNameForKind, then
// compares that against a policy's matchConstraints.resourceRules[].resources
// list. If a policy targets a resource name (e.g. "kubevirts") that no Kind
// in internal/loader/kinds.go's kindToResource map actually produces, the
// policy compiles fine, LoadBuiltin() succeeds, and the policy simply never
// matches anything — forever, silently, with zero findings and zero log
// output at any verbosity. TestThirdPartyPolicyFixtures only catches this
// if someone also wrote a fixture for the broken policy (see
// TestEveryThirdPartyPolicyHasFixtures in thirdparty_fixtures_test.go for
// the complementary "did we even write fixtures" check). This test closes
// the gap directly: it fails loudly, naming the exact policy and resource,
// the moment a new check's resources: entry has no matching kindToResource
// registration — the same silent-failure shape that has already cost real
// debugging time in this repo's history.
import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/engine"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

func TestBuiltinPolicyResourcesResolveToARegisteredKind(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	for _, p := range policies {
		mc := p.Policy.Spec.MatchConstraints
		if mc == nil {
			continue
		}
		for _, rule := range mc.ResourceRules {
			for _, r := range rule.Resources {
				if r == "*" {
					continue
				}
				if !loader.IsKnownResource(r) {
					t.Errorf("policy %q: matchConstraints.resourceRules targets resource %q, but no Kind in internal/loader/kinds.go's kindToResource map produces it — this policy can never match any resource, ever. Register the Kind (e.g. \"YourKind\": %q) in internal/loader/kinds.go.", p.Meta.ID, r, r)
				}
			}
		}
	}
}
