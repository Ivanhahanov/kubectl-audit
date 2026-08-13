package cli

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

func resourceWithSource(source string) loader.Resource {
	return loader.Resource{
		Object: &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   map[string]any{"name": "cm"},
		}},
		Source: source,
	}
}

func TestHasMultipleSources_SingleFile(t *testing.T) {
	resources := []loader.Resource{
		resourceWithSource("/manifests/a.yaml"),
		resourceWithSource("/manifests/a.yaml"),
	}
	if hasMultipleSources(resources) {
		t.Error("expected false when every resource came from the same source")
	}
}

func TestHasMultipleSources_MultipleFiles(t *testing.T) {
	resources := []loader.Resource{
		resourceWithSource("/manifests/a.yaml"),
		resourceWithSource("/manifests/b.yaml"),
	}
	if !hasMultipleSources(resources) {
		t.Error("expected true when resources came from different sources")
	}
}

func TestHasMultipleSources_Empty(t *testing.T) {
	if hasMultipleSources(nil) {
		t.Error("expected false for no resources")
	}
}
