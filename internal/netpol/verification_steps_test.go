package netpol_test

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/netpol"
)

// TestEveryCheckHasVerificationSteps guards the triage-tool content
// requirement (see docs/triage.md): all three known check IDs
// (no-network-policy-coverage, broad-namespace-selector-rule,
// no-egress-restriction) must produce findings with a non-empty
// VerificationSteps.
func TestEveryCheckHasVerificationSteps(t *testing.T) {
	uncovered := mustResource(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: default
spec:
  selector:
    matchLabels: {app: app}
  template:
    metadata:
      labels: {app: app}
    spec:
      containers: [{name: c, image: nginx}]
`)
	broadSelectorPolicy := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: broad
  namespace: other
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - namespaceSelector: {}
`)

	coverageFindings, err := netpol.Analyze([]loader.Resource{uncovered}, "test")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	reachabilityFindings, err := netpol.AnalyzeReachability([]loader.Resource{uncovered, broadSelectorPolicy}, "test")
	if err != nil {
		t.Fatalf("AnalyzeReachability: %v", err)
	}

	want := map[string]bool{
		netpol.CheckID:                       false,
		netpol.CheckIDBroadNamespaceSelector: false,
		netpol.CheckIDNoEgressRestriction:    false,
	}
	for _, f := range append(coverageFindings, reachabilityFindings...) {
		if _, known := want[f.PolicyID]; known {
			want[f.PolicyID] = true
		}
		if f.VerificationSteps == "" {
			t.Errorf("finding %s has no VerificationSteps", f.PolicyID)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("expected a %s finding from this fixture set", id)
		}
	}
}
