package engine_test

// TestBuiltinPolicyResourcesAreFetchedFromCluster guards against a
// previously-real, higher-impact bug class than the kinds.go one: a
// policy's matchConstraints.resourceRules can name a (group, resource) pair
// that the Kind is correctly registered for in internal/loader/kinds.go
// (so TestBuiltinPolicyResourcesResolveToARegisteredKind passes, and the
// check even fires correctly against a static manifest fixture in
// TestThirdPartyPolicyFixtures) — but if that same (group, resource) pair
// isn't also enumerated in internal/loader/cluster.go's defaultResources or
// optionalResources, LoadCluster never asks the API server for it, so the
// check can never produce a single finding against a real `kubectl audit
// scan` of a live cluster. This exact gap was found live in this repo: six
// third-party components' checks (Kyverno, KubeVirt, APISIX, several Istio
// checks, Calico's FelixConfiguration checks, ArgoCD Application, Vault
// VaultAuth, VictoriaMetrics VMAuth/VMAgent) worked perfectly in every test
// and in -f static-manifest mode while being structurally unreachable in
// live-cluster mode, with nothing in the test suite ever noticing.
import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/engine"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// legacyGroupsNeverFetchedFromCluster are API groups a policy deliberately
// targets ONLY for -f static-manifest mode (old backups/repos), never live:
// current Kubernetes API servers (1.22+) don't serve them at all, so
// there's nothing for LoadCluster to fetch and no optionalResources entry
// would ever resolve. "extensions" (v1beta1 Ingress) is the one bundled
// example — network.no-deprecated-ingress-api-version and
// network.ingress-tls-required's old-API-version fixture both exist
// specifically to catch this shape in a static manifest.
var legacyGroupsNeverFetchedFromCluster = map[string]bool{
	"extensions": true,
}

func TestBuiltinPolicyResourcesAreFetchedFromCluster(t *testing.T) {
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
			for _, g := range rule.APIGroups {
				if g == "*" || legacyGroupsNeverFetchedFromCluster[g] {
					continue
				}
				for _, r := range rule.Resources {
					if r == "*" {
						continue
					}
					if !loader.IsFetchableFromCluster(g, r) {
						t.Errorf("policy %q: matchConstraints.resourceRules targets group %q resource %q, but internal/loader/cluster.go's defaultResources/optionalResources never fetch it — this policy can work in -f static-manifest mode and in fixture tests but can never fire against a live `scan`. Add {Group: %q, Resource: %q, ...} to optionalResources (or defaultResources, if it's a built-in kind).", p.Meta.ID, g, r, g, r)
					}
				}
			}
		}
	}
}
