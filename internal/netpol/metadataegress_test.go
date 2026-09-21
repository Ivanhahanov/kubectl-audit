package netpol_test

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/netpol"
)

func metadataEgressPolicyIDs(t *testing.T, resources []loader.Resource) map[string]int {
	t.Helper()
	found, err := netpol.AnalyzeMetadataEgress(resources, "test")
	if err != nil {
		t.Fatalf("AnalyzeMetadataEgress: %v", err)
	}
	out := map[string]int{}
	for _, f := range found {
		out[f.PolicyID]++
	}
	return out
}

func metadataEgressPod(t *testing.T) loader.Resource {
	t.Helper()
	return mustResource(t, `
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
}

func TestMetadataEgress_EmptyToListFlagged(t *testing.T) {
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress
  namespace: default
spec:
  podSelector:
    matchLabels: {app: app}
  policyTypes: ["Egress"]
  egress:
    - to: []
`)
	ids := metadataEgressPolicyIDs(t, []loader.Resource{metadataEgressPod(t), np})
	if ids[netpol.CheckIDEgressToMetadataAllowed] != 1 {
		t.Errorf("expected egress-to-metadata-allowed to fire on an empty \"to\" rule, got %+v", ids)
	}
}

func TestMetadataEgress_WideOpenIPBlockFlagged(t *testing.T) {
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress
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
	ids := metadataEgressPolicyIDs(t, []loader.Resource{metadataEgressPod(t), np})
	if ids[netpol.CheckIDEgressToMetadataAllowed] != 1 {
		t.Errorf("expected egress-to-metadata-allowed to fire on a 0.0.0.0/0 ipBlock, got %+v", ids)
	}
}

func TestMetadataEgress_ExceptCarveOutNotFlagged(t *testing.T) {
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress
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
	ids := metadataEgressPolicyIDs(t, []loader.Resource{metadataEgressPod(t), np})
	if ids[netpol.CheckIDEgressToMetadataAllowed] != 0 {
		t.Errorf("expected no finding when except explicitly excludes the metadata IP, got %+v", ids)
	}
}

func TestMetadataEgress_ScopedIPBlockNotFlagged(t *testing.T) {
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress
  namespace: default
spec:
  podSelector:
    matchLabels: {app: app}
  policyTypes: ["Egress"]
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8
`)
	ids := metadataEgressPolicyIDs(t, []loader.Resource{metadataEgressPod(t), np})
	if len(ids) != 0 {
		t.Errorf("expected no finding when the ipBlock doesn't cover the metadata IP at all, got %+v", ids)
	}
}

func TestMetadataEgress_NoEgressCoverageAtAllSkipped(t *testing.T) {
	ids := metadataEgressPolicyIDs(t, []loader.Resource{metadataEgressPod(t)})
	if len(ids) != 0 {
		t.Errorf("expected zero-egress-coverage workloads to be skipped (that's no-egress-restriction's job), got %+v", ids)
	}
}
