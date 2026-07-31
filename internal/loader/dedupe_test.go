package loader_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

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

func TestDedupeByOwnerChainDropsOwnedPodAndReplicaSet(t *testing.T) {
	deployment := mustResource(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: default
  uid: dep-uid
spec:
  template:
    spec:
      containers: []
`)
	replicaSet := mustResource(t, `
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: app-abc123
  namespace: default
  uid: rs-uid
  ownerReferences:
    - apiVersion: apps/v1
      kind: Deployment
      name: app
      uid: dep-uid
      controller: true
spec:
  template:
    spec:
      containers: []
`)
	pod := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: app-abc123-xyz
  namespace: default
  uid: pod-uid
  ownerReferences:
    - apiVersion: apps/v1
      kind: ReplicaSet
      name: app-abc123
      uid: rs-uid
      controller: true
spec:
  containers: []
`)

	out := loader.DedupeByOwnerChain([]loader.Resource{deployment, replicaSet, pod})
	if len(out) != 1 {
		t.Fatalf("expected only the Deployment to survive dedup, got %d: %+v", len(out), out)
	}
	if out[0].GVK().Kind != "Deployment" {
		t.Errorf("expected the surviving resource to be the Deployment, got %s", out[0].GVK().Kind)
	}
}

func TestDedupeByOwnerChainKeepsOrphanedResources(t *testing.T) {
	// A ReplicaSet whose owning Deployment was NOT loaded (e.g. filtered
	// out by --exclude-kind) must be kept, or its template disappears
	// entirely.
	replicaSet := mustResource(t, `
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: orphan-rs
  namespace: default
  uid: rs-uid
  ownerReferences:
    - apiVersion: apps/v1
      kind: Deployment
      name: not-loaded
      uid: missing-uid
      controller: true
spec:
  template:
    spec:
      containers: []
`)
	bareStaticPod := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: static-pod
  namespace: kube-system
  uid: static-uid
spec:
  containers: []
`)

	out := loader.DedupeByOwnerChain([]loader.Resource{replicaSet, bareStaticPod})
	if len(out) != 2 {
		t.Fatalf("expected both resources to be kept (owner not loaded / no owner), got %d: %+v", len(out), out)
	}
}

func TestFilterExcludedNamespaces(t *testing.T) {
	kubeSystemPod := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: p
  namespace: kube-system
spec:
  containers: []
`)
	kubeSystemNS := mustResource(t, `
apiVersion: v1
kind: Namespace
metadata:
  name: kube-system
`)
	appPod := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: default
spec:
  containers: []
`)
	clusterRole := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: some-role
rules: []
`)

	out := loader.FilterExcludedNamespaces(
		[]loader.Resource{kubeSystemPod, kubeSystemNS, appPod, clusterRole},
		[]string{"kube-system"},
	)
	if len(out) != 2 {
		t.Fatalf("expected 2 resources to survive (appPod, clusterRole), got %d: %+v", len(out), out)
	}
	for _, r := range out {
		if r.Namespace() == "kube-system" || (r.GVK().Kind == "Namespace" && r.Name() == "kube-system") {
			t.Errorf("expected kube-system resources to be filtered out, found %+v", r)
		}
	}
}

func TestFilterExcludedNamespacesNoOpWhenEmpty(t *testing.T) {
	pod := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: p
  namespace: kube-system
spec:
  containers: []
`)
	out := loader.FilterExcludedNamespaces([]loader.Resource{pod}, nil)
	if len(out) != 1 {
		t.Fatalf("expected no filtering with an empty exclude list, got %d", len(out))
	}
}

func TestFilterSystemRBAC(t *testing.T) {
	systemRole := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: "system:controller:namespace-controller"
rules: []
`)
	systemBinding := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: "system:public-info-viewer"
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:public-info-viewer
subjects: []
`)
	adminBinding := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects: []
`)
	pod := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: p
  namespace: default
spec:
  containers: []
`)

	out := loader.FilterSystemRBAC([]loader.Resource{systemRole, systemBinding, adminBinding, pod})
	if len(out) != 2 {
		t.Fatalf("expected system:-prefixed RBAC objects to be dropped, kept %d: %+v", len(out), out)
	}
	for _, r := range out {
		if r.Name() == "system:controller:namespace-controller" || r.Name() == "system:public-info-viewer" {
			t.Errorf("expected system:-prefixed RBAC object %q to be filtered", r.Name())
		}
	}
}
