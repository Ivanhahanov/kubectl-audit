package apideprecations_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/ivanhahanov/kubectl-audit/internal/apideprecations"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

func resource(apiVersion, kind, name string) loader.Resource {
	return loader.Resource{Object: &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata":   map[string]any{"name": name, "namespace": "default"},
	}}, Source: "test"}
}

func TestAnalyzeRemovedOnTargetVersionIsCritical(t *testing.T) {
	// extensions/v1beta1 Ingress was removed in v1.22.
	out := apideprecations.Analyze([]loader.Resource{resource("extensions/v1beta1", "Ingress", "old")}, "v1.25.0", "test")
	if len(out) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", out)
	}
	if out[0].Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL severity for an already-removed API on the target version, got %s", out[0].Severity)
	}
}

func TestAnalyzeRemovedInFutureVersionIsHighNotCritical(t *testing.T) {
	// Still works on v1.20 (removed in v1.22, which is later).
	out := apideprecations.Analyze([]loader.Resource{resource("extensions/v1beta1", "Ingress", "old")}, "v1.20.0", "test")
	if len(out) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", out)
	}
	if out[0].Severity != "HIGH" {
		t.Errorf("expected HIGH severity for an API not yet removed on the target version, got %s", out[0].Severity)
	}
}

func TestAnalyzeCurrentAPIVersionIgnored(t *testing.T) {
	out := apideprecations.Analyze([]loader.Resource{resource("networking.k8s.io/v1", "Ingress", "fine")}, "v1.25.0", "test")
	if len(out) != 0 {
		t.Errorf("expected no findings for the current stable apiVersion, got %+v", out)
	}
}

func TestAnalyzeEmptyVersionFallsBackToLatestKnown(t *testing.T) {
	// No live cluster (static-manifest-only scan): should assume "current"
	// and flag anything already removed as of the latest known version.
	out := apideprecations.Analyze([]loader.Resource{resource("extensions/v1beta1", "Ingress", "old")}, "", "test")
	if len(out) != 1 || out[0].Severity != "CRITICAL" {
		t.Fatalf("expected a CRITICAL finding falling back to the latest known version, got %+v", out)
	}
}

func TestStaleWarning(t *testing.T) {
	if got := apideprecations.StaleWarning("v1.36.0"); got != "" {
		t.Errorf("expected no stale warning at k8sversion.LatestKnownMinor, got %q", got)
	}
	if got := apideprecations.StaleWarning("v1.99.0"); got == "" {
		t.Error("expected a stale warning far past k8sversion.LatestKnownMinor")
	}
	if got := apideprecations.StaleWarning(""); got != "" {
		t.Errorf("expected no stale warning for an unparseable version, got %q", got)
	}
}
