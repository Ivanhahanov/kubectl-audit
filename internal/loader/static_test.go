package loader_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

func TestLoadStaticMultiDocSkipsEmpty(t *testing.T) {
	dir := t.TempDir()
	content := `
apiVersion: v1
kind: Pod
metadata:
  name: a
  namespace: default
spec:
  containers: []
---
---
apiVersion: v1
kind: Pod
metadata:
  name: b
  namespace: default
spec:
  containers: []
`
	if err := os.WriteFile(filepath.Join(dir, "multi.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	resources, err := loader.LoadStatic([]string{dir})
	if err != nil {
		t.Fatalf("LoadStatic: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources (empty docs skipped), got %d", len(resources))
	}
	names := map[string]bool{}
	for _, r := range resources {
		names[r.Name()] = true
	}
	if !names["a"] || !names["b"] {
		t.Errorf("expected pods 'a' and 'b', got %v", names)
	}
}

func TestLoadStaticListKindFlattened(t *testing.T) {
	dir := t.TempDir()
	content := `
apiVersion: v1
kind: PodList
items:
  - apiVersion: v1
    kind: Pod
    metadata:
      name: from-list
      namespace: default
    spec:
      containers: []
`
	if err := os.WriteFile(filepath.Join(dir, "list.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	resources, err := loader.LoadStatic([]string{dir})
	if err != nil {
		t.Fatalf("LoadStatic: %v", err)
	}
	if len(resources) != 1 || resources[0].Name() != "from-list" {
		t.Fatalf("expected the PodList to flatten into 1 Pod resource, got %+v", resources)
	}
}

func TestLoadStaticRecursesDirectories(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	content := `
apiVersion: v1
kind: Namespace
metadata:
  name: nested-ns
`
	if err := os.WriteFile(filepath.Join(sub, "ns.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	resources, err := loader.LoadStatic([]string{dir})
	if err != nil {
		t.Fatalf("LoadStatic: %v", err)
	}
	if len(resources) != 1 || resources[0].Name() != "nested-ns" {
		t.Fatalf("expected to find the nested Namespace, got %+v", resources)
	}
}
