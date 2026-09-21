package netpol_test

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/netpol"
)

func allowAllPolicyIDs(t *testing.T, resources []loader.Resource) map[string]int {
	t.Helper()
	found, err := netpol.AnalyzeAllowAllModel(resources, "test")
	if err != nil {
		t.Fatalf("AnalyzeAllowAllModel: %v", err)
	}
	out := map[string]int{}
	for _, f := range found {
		out[f.PolicyID]++
	}
	return out
}

func TestAllowAllModel_EmptyIngressPeerListFlagged(t *testing.T) {
	pod := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: default
  labels:
    app: app
spec:
  containers: [{name: c, image: nginx}]
`)
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: nominal
  namespace: default
spec:
  podSelector:
    matchLabels: {app: app}
  policyTypes: ["Ingress"]
  ingress:
    - from: []
`)
	ids := allowAllPolicyIDs(t, []loader.Resource{pod, np})
	if ids[netpol.CheckIDIngressAllowAllRule] != 1 {
		t.Errorf("expected ingress-allow-all-rule to fire on an empty \"from\" rule, got %+v", ids)
	}
	if ids[netpol.CheckIDEgressAllowAllRule] != 0 {
		t.Errorf("expected no egress-allow-all-rule (policy doesn't cover egress at all), got %+v", ids)
	}
}

func TestAllowAllModel_WideOpenIPBlockFlagged(t *testing.T) {
	pod := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: default
  labels:
    app: app
spec:
  containers: [{name: c, image: nginx}]
`)
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: nominal
  namespace: default
spec:
  podSelector:
    matchLabels: {app: app}
  policyTypes: ["Egress"]
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
`)
	ids := allowAllPolicyIDs(t, []loader.Resource{pod, np})
	if ids[netpol.CheckIDEgressAllowAllRule] != 1 {
		t.Errorf("expected egress-allow-all-rule to fire on a bare 0.0.0.0/0 ipBlock, got %+v", ids)
	}
}

func TestAllowAllModel_ScopedRuleNotFlagged(t *testing.T) {
	pod := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: default
  labels:
    app: app
spec:
  containers: [{name: c, image: nginx}]
`)
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scoped
  namespace: default
spec:
  podSelector:
    matchLabels: {app: app}
  policyTypes: ["Ingress", "Egress"]
  ingress:
    - from:
        - podSelector:
            matchLabels: {app: frontend}
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8
`)
	ids := allowAllPolicyIDs(t, []loader.Resource{pod, np})
	if len(ids) != 0 {
		t.Errorf("expected no allow-all findings on scoped rules, got %+v", ids)
	}
}

func TestAllowAllModel_ExceptCarveOutNotFlagged(t *testing.T) {
	pod := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: default
  labels:
    app: app
spec:
  containers: [{name: c, image: nginx}]
`)
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: carve-out
  namespace: default
spec:
  podSelector:
    matchLabels: {app: app}
  policyTypes: ["Egress"]
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except: ["169.254.169.254/32"]
`)
	ids := allowAllPolicyIDs(t, []loader.Resource{pod, np})
	if ids[netpol.CheckIDEgressAllowAllRule] != 0 {
		t.Errorf("expected no egress-allow-all-rule finding: 0.0.0.0/0 with a non-empty except is not an unrestricted rule under this check's definition, got %+v", ids)
	}
}

func TestAllowAllModel_NoCoverageAtAllNotFlagged(t *testing.T) {
	pod := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: default
  labels:
    app: app
spec:
  containers: [{name: c, image: nginx}]
`)
	ids := allowAllPolicyIDs(t, []loader.Resource{pod})
	if len(ids) != 0 {
		t.Errorf("expected zero-coverage workloads to be skipped (that's no-network-policy-coverage/no-egress-restriction's job), got %+v", ids)
	}
}
