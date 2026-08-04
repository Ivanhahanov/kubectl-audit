package cli

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/ivanhahanov/kubectl-audit/internal/config"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

func rbacResource() loader.Resource {
	return loader.Resource{Object: &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "Role",
		"metadata":   map[string]any{"name": "r", "namespace": "default"},
	}}}
}

func netpolResource() loader.Resource {
	return loader.Resource{Object: &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata":   map[string]any{"name": "np", "namespace": "default"},
	}}}
}

func TestBuildScope_SingleManifestStatic(t *testing.T) {
	cfg := &config.AuditConfig{Target: config.TargetConfig{Mode: config.ModeStatic}}
	scope := buildScope(cfg, nil, "", map[string]bool{})

	titles := map[string]bool{}
	for _, n := range scope.OutOfScope {
		titles[n.Title] = true
	}
	if !titles["RBAC least-privilege analysis"] {
		t.Error("expected an RBAC scope note for a static scan with no RBAC objects")
	}
	if !titles["NetworkPolicy coverage"] {
		t.Error("expected a NetworkPolicy scope note for a static scan with no NetworkPolicy objects")
	}
	if len(scope.OutOfScope) < 4 {
		t.Errorf("expected control-plane and version notes too, got %+v", scope.OutOfScope)
	}
}

func TestBuildScope_FullClusterNoGaps(t *testing.T) {
	cfg := &config.AuditConfig{Target: config.TargetConfig{Mode: config.ModeCluster}}
	resources := []loader.Resource{rbacResource(), netpolResource()}
	observed := map[string]bool{"apiserver": true, "controller-manager": true, "scheduler": true, "etcd": true}

	scope := buildScope(cfg, resources, "v1.30.0", observed)
	if len(scope.OutOfScope) != 0 {
		t.Errorf("expected no scope gaps for a fully-observed live cluster, got %+v", scope.OutOfScope)
	}
}

func TestBuildScope_ManagedClusterControlPlaneNotObserved(t *testing.T) {
	cfg := &config.AuditConfig{Target: config.TargetConfig{Mode: config.ModeCluster}}
	resources := []loader.Resource{rbacResource(), netpolResource()}
	observed := map[string]bool{} // nothing observed, e.g. EKS/GKE/AKS

	scope := buildScope(cfg, resources, "v1.30.0", observed)
	if len(scope.OutOfScope) != 1 {
		t.Fatalf("expected exactly one scope note (control-plane), got %+v", scope.OutOfScope)
	}
	if scope.OutOfScope[0].Title == "" {
		t.Error("expected a non-empty title")
	}
}

func TestBuildScope_StaticWithRBACAndNetPolPresent(t *testing.T) {
	cfg := &config.AuditConfig{Target: config.TargetConfig{Mode: config.ModeStatic}}
	resources := []loader.Resource{rbacResource(), netpolResource()}

	scope := buildScope(cfg, resources, "", map[string]bool{})
	var rbacNote, netpolNote string
	for _, n := range scope.OutOfScope {
		switch n.Title {
		case "RBAC least-privilege analysis":
			rbacNote = n.Reason
		case "NetworkPolicy coverage":
			netpolNote = n.Reason
		}
	}
	if rbacNote == "" || netpolNote == "" {
		t.Fatalf("expected both RBAC and NetworkPolicy notes even when objects are present (static scans are still incomplete by nature), got %+v", scope.OutOfScope)
	}
	// When objects ARE present, the wording should talk about completeness,
	// not "nothing to analyze".
	if strings.Contains(rbacNote, "there's nothing to analyze") {
		t.Errorf("expected the 'objects present' wording, got the 'no objects' wording: %q", rbacNote)
	}
}
