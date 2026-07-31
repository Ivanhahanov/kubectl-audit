package netpol_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/netpol"
)

func mustResource(t *testing.T, doc string) loader.Resource {
	t.Helper()
	var m map[string]interface{}
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	return loader.Resource{Object: &unstructured.Unstructured{Object: m}, Source: "test"}
}

func hasFinding(list []netpolFinding, name string) bool {
	for _, f := range list {
		if f.Resource == name {
			return true
		}
	}
	return false
}

// netpolFinding is a tiny local projection to keep test assertions readable.
type netpolFinding struct{ Resource string }

func projectFindings(t *testing.T, resources []loader.Resource) []netpolFinding {
	t.Helper()
	found, err := netpol.Analyze(resources, "test")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	out := make([]netpolFinding, 0, len(found))
	for _, f := range found {
		out = append(out, netpolFinding{Resource: f.Resource.Name})
	}
	return out
}

func TestUncoveredWorkloadFlagged(t *testing.T) {
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
	found := projectFindings(t, []loader.Resource{deployment})
	if !hasFinding(found, "app") {
		t.Errorf("expected a finding for an uncovered workload, got %+v", found)
	}
}

func TestCoveredByMatchingNativePolicy(t *testing.T) {
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
  name: deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
`)
	found := projectFindings(t, []loader.Resource{deployment, np})
	if hasFinding(found, "app") {
		t.Errorf("expected no finding: an empty podSelector NetworkPolicy covers every pod in the namespace, got %+v", found)
	}
}

func TestNotCoveredByNonMatchingSelector(t *testing.T) {
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
  name: other-app-only
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: some-other-app
  policyTypes: ["Ingress"]
`)
	found := projectFindings(t, []loader.Resource{deployment, np})
	if !hasFinding(found, "app") {
		t.Errorf("expected a finding: the NetworkPolicy selects a different app, got %+v", found)
	}
}

func TestEgressOnlyPolicyDoesNotCoverIngress(t *testing.T) {
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
  podSelector: {}
  policyTypes: ["Egress"]
`)
	found := projectFindings(t, []loader.Resource{deployment, np})
	if !hasFinding(found, "app") {
		t.Errorf("expected a finding: an egress-only policy leaves ingress unrestricted, got %+v", found)
	}
}

func TestCiliumPresenceSuppressesFinding(t *testing.T) {
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
	cnp := mustResource(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: some-policy
  namespace: default
spec: {}
`)
	found := projectFindings(t, []loader.Resource{deployment, cnp})
	if hasFinding(found, "app") {
		t.Errorf("expected no finding: a CiliumNetworkPolicy in the namespace is treated as a coverage signal, got %+v", found)
	}
}

func TestClusterWideCalicoPolicySuppressesFindingEverywhere(t *testing.T) {
	deployment := mustResource(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: other-ns
spec:
  template:
    metadata:
      labels:
        app: app
    spec:
      containers: []
`)
	gnp := mustResource(t, `
apiVersion: crd.projectcalico.org/v1
kind: GlobalNetworkPolicy
metadata:
  name: cluster-wide
spec: {}
`)
	found := projectFindings(t, []loader.Resource{deployment, gnp})
	if hasFinding(found, "app") {
		t.Errorf("expected no finding: a cluster-wide Calico GlobalNetworkPolicy is a conservative coverage signal for every namespace, got %+v", found)
	}
}

func TestCronJobPodTemplateLabelsExtracted(t *testing.T) {
	cj := mustResource(t, `
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
  namespace: default
spec:
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            app: nightly
        spec:
          containers: []
`)
	np := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: covers-nightly
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: nightly
  policyTypes: ["Ingress"]
`)
	found := projectFindings(t, []loader.Resource{cj, np})
	if hasFinding(found, "nightly") {
		t.Errorf("expected no finding: the policy matches the CronJob's nested jobTemplate pod labels, got %+v", found)
	}
}

func TestClusterScopedWorkloadsIgnored(t *testing.T) {
	// Sanity: a Namespace object itself must never be treated as a workload.
	ns := mustResource(t, `
apiVersion: v1
kind: Namespace
metadata:
  name: default
`)
	found := projectFindings(t, []loader.Resource{ns})
	if len(found) != 0 {
		t.Errorf("expected no findings for a Namespace object, got %+v", found)
	}
}
