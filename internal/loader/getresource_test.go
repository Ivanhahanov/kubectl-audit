package loader

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/ivanhahanov/kubectl-audit/internal/k8sclient"
)

func fakeClientWithObjects(objs ...*unstructured.Unstructured) *k8sclient.Client {
	scheme := runtime.NewScheme()
	gvrToKind := map[schema.GroupVersionResource]string{
		{Group: "apps", Version: "v1", Resource: "deployments"}: "DeploymentList",
		{Group: "", Version: "v1", Resource: "namespaces"}:      "NamespaceList",
	}
	runtimeObjs := make([]runtime.Object, len(objs))
	for i, o := range objs {
		runtimeObjs[i] = o
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToKind, runtimeObjs...)
	return &k8sclient.Client{Dynamic: dyn}
}

func newUnstructured(apiVersion, kind, namespace, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata":   map[string]any{"name": name, "namespace": namespace},
	}}
}

func TestGetResource_NamespacedBuiltin(t *testing.T) {
	dep := newUnstructured("apps/v1", "Deployment", "default", "web")
	c := fakeClientWithObjects(dep)

	res, err := GetResource(context.Background(), c, "Deployment", "default", "web")
	if err != nil {
		t.Fatalf("GetResource: %v", err)
	}
	if res.Name() != "web" || res.Namespace() != "default" {
		t.Errorf("got %s/%s, want default/web", res.Namespace(), res.Name())
	}
}

func TestGetResource_ClusterScopedBuiltin(t *testing.T) {
	ns := newUnstructured("v1", "Namespace", "", "kube-system")
	c := fakeClientWithObjects(ns)

	res, err := GetResource(context.Background(), c, "Namespace", "", "kube-system")
	if err != nil {
		t.Fatalf("GetResource: %v", err)
	}
	if res.Name() != "kube-system" {
		t.Errorf("Name = %q, want kube-system", res.Name())
	}
}

func TestGetResource_SecretAlwaysRejected(t *testing.T) {
	c := fakeClientWithObjects()
	_, err := GetResource(context.Background(), c, "Secret", "default", "x")
	if err == nil {
		t.Fatal("expected an error for kind Secret, got nil")
	}
}

func TestGetResource_UnknownKind(t *testing.T) {
	c := fakeClientWithObjects()
	_, err := GetResource(context.Background(), c, "NotARealKind", "default", "x")
	if err == nil {
		t.Fatal("expected an error for an unknown kind, got nil")
	}
}

func TestGetResource_NotFound(t *testing.T) {
	c := fakeClientWithObjects()
	_, err := GetResource(context.Background(), c, "Deployment", "default", "does-not-exist")
	if err == nil {
		t.Fatal("expected a not-found error, got nil")
	}
}
