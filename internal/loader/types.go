// Package loader builds a unified list of Kubernetes resources to audit,
// whether they come from a live cluster or static manifest files.
package loader

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Resource wraps a Kubernetes object together with where it came from, so
// findings can point back at a cluster or a specific manifest file.
type Resource struct {
	Object *unstructured.Unstructured
	Source string
}

// GVK returns the object's GroupVersionKind.
func (r Resource) GVK() schema.GroupVersionKind {
	return r.Object.GroupVersionKind()
}

// Namespace returns the object's namespace (empty for cluster-scoped kinds).
func (r Resource) Namespace() string { return r.Object.GetNamespace() }

// Name returns the object's name.
func (r Resource) Name() string { return r.Object.GetName() }
