package netpol_test

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/netpol"
)

// TestEveryCheckHasVerificationSteps guards the triage-tool content
// requirement (see docs/triage.md): every known check ID in this package
// must produce findings with a non-empty VerificationSteps.
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

	allowAllApp := mustResource(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: allow-all-app
  namespace: allow-all
spec:
  selector:
    matchLabels: {app: allow-all-app}
  template:
    metadata:
      labels: {app: allow-all-app}
    spec:
      containers: [{name: c, image: nginx}]
`)
	allowAllPolicy := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: nominal
  namespace: allow-all
spec:
  podSelector:
    matchLabels: {app: allow-all-app}
  policyTypes: ["Ingress", "Egress"]
  ingress:
    - from: []
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
`)

	coverageFindings, err := netpol.Analyze([]loader.Resource{uncovered}, "test")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	reachabilityFindings, err := netpol.AnalyzeReachability([]loader.Resource{uncovered, broadSelectorPolicy}, "test")
	if err != nil {
		t.Fatalf("AnalyzeReachability: %v", err)
	}
	allowAllFindings, err := netpol.AnalyzeAllowAllModel([]loader.Resource{allowAllApp, allowAllPolicy}, "test")
	if err != nil {
		t.Fatalf("AnalyzeAllowAllModel: %v", err)
	}
	metadataEgressFindings, err := netpol.AnalyzeMetadataEgress([]loader.Resource{allowAllApp, allowAllPolicy}, "test")
	if err != nil {
		t.Fatalf("AnalyzeMetadataEgress: %v", err)
	}

	want := map[string]bool{
		netpol.CheckID:                        false,
		netpol.CheckIDBroadNamespaceSelector:  false,
		netpol.CheckIDNoEgressRestriction:     false,
		netpol.CheckIDIngressAllowAllRule:     false,
		netpol.CheckIDEgressAllowAllRule:      false,
		netpol.CheckIDEgressToMetadataAllowed: false,
	}
	all := append(coverageFindings, reachabilityFindings...)
	all = append(all, allowAllFindings...)
	all = append(all, metadataEgressFindings...)
	for _, f := range all {
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
