package netpol_test

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/netpol"
)

func policyIDs(t *testing.T, resources []loader.Resource) map[string]int {
	t.Helper()
	found, err := netpol.AnalyzeReachability(resources, "test")
	if err != nil {
		t.Fatalf("AnalyzeReachability: %v", err)
	}
	out := map[string]int{}
	for _, f := range found {
		out[f.PolicyID]++
	}
	return out
}

func TestBroadNamespaceSelector_Flagged(t *testing.T) {
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: broad
  namespace: default
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              team: platform
`)
	ids := policyIDs(t, []loader.Resource{np})
	if ids[netpol.CheckIDBroadNamespaceSelector] != 1 {
		t.Errorf("expected exactly one broad-namespace-selector finding, got %+v", ids)
	}
}

func TestBroadNamespaceSelector_EmptySelectorStillFlagged(t *testing.T) {
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: wide-open
  namespace: default
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - namespaceSelector: {}
`)
	ids := policyIDs(t, []loader.Resource{np})
	if ids[netpol.CheckIDBroadNamespaceSelector] != 1 {
		t.Errorf("expected an empty namespaceSelector to be flagged too, got %+v", ids)
	}
}

func TestBroadNamespaceSelector_NotFlaggedWithPodSelector(t *testing.T) {
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scoped
  namespace: default
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              team: platform
          podSelector:
            matchLabels:
              app: frontend
`)
	ids := policyIDs(t, []loader.Resource{np})
	if ids[netpol.CheckIDBroadNamespaceSelector] != 0 {
		t.Errorf("expected no finding when podSelector accompanies namespaceSelector, got %+v", ids)
	}
}

func TestNoEgressRestriction_Flagged(t *testing.T) {
	deployment := mustResource(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: default
spec:
  template:
    metadata:
      labels:
        app: app
    spec:
      containers: []
`)
	ids := policyIDs(t, []loader.Resource{deployment})
	if ids[netpol.CheckIDNoEgressRestriction] != 1 {
		t.Errorf("expected an egress-restriction finding for an uncovered workload, got %+v", ids)
	}
}

func TestNoEgressRestriction_CoveredByExplicitEgressType(t *testing.T) {
	deployment := mustResource(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: default
spec:
  template:
    metadata:
      labels:
        app: app
    spec:
      containers: []
`)
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress-only
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: app
  policyTypes: ["Egress"]
  egress: []
`)
	ids := policyIDs(t, []loader.Resource{deployment, np})
	if ids[netpol.CheckIDNoEgressRestriction] != 0 {
		t.Errorf("expected the explicit Egress-type policy to count as coverage even with zero rules (deny-all), got %+v", ids)
	}
}

func TestNoEgressRestriction_NotImpliedByIngressOnlyPolicy(t *testing.T) {
	deployment := mustResource(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: default
spec:
  template:
    metadata:
      labels:
        app: app
    spec:
      containers: []
`)
	// PolicyTypes omitted entirely: defaults to Ingress only, since there
	// are no Egress rules — must NOT be treated as covering egress.
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-only
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: app
  ingress:
    - from: []
`)
	ids := policyIDs(t, []loader.Resource{deployment, np})
	if ids[netpol.CheckIDNoEgressRestriction] != 1 {
		t.Errorf("expected an ingress-only policy (implicit PolicyTypes) to NOT count as egress coverage, got %+v", ids)
	}
}

func TestNoEgressRestriction_ImpliedByPresentEgressRules(t *testing.T) {
	deployment := mustResource(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: default
spec:
  template:
    metadata:
      labels:
        app: app
    spec:
      containers: []
`)
	// PolicyTypes omitted, but Egress rules are present: per the
	// NetworkPolicy API's defaulting behavior this implies Egress too.
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: implicit-egress
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: app
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: db
`)
	ids := policyIDs(t, []loader.Resource{deployment, np})
	if ids[netpol.CheckIDNoEgressRestriction] != 0 {
		t.Errorf("expected implicit PolicyTypes with present Egress rules to count as coverage, got %+v", ids)
	}
}
