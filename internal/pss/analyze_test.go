package pss

import (
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

func mustResource(t *testing.T, obj map[string]any) loader.Resource {
	t.Helper()
	return loader.Resource{Object: &unstructured.Unstructured{Object: obj}, Source: "test"}
}

func privilegedPod(name string) loader.Resource {
	return loader.Resource{Object: &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": name, "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{
					"name":  "c",
					"image": "nginx",
					"securityContext": map[string]any{
						"privileged": true,
					},
				},
			},
		},
	}}, Source: "test"}
}

func restrictedViolatingPod(name string) loader.Resource {
	// Passes Baseline (no privileged/host namespaces/hostPath/hostPorts/bad
	// capabilities) but fails Restricted (no runAsNonRoot, no seccomp, caps
	// not fully dropped, allowPrivilegeEscalation not false).
	return loader.Resource{Object: &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": name, "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{
					"name":  "c",
					"image": "nginx",
				},
			},
		},
	}}, Source: "test"}
}

func fullyRestrictedCompliantPod(name string) loader.Resource {
	return loader.Resource{Object: &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": name, "namespace": "default"},
		"spec": map[string]any{
			"securityContext": map[string]any{
				"runAsNonRoot": true,
				"seccompProfile": map[string]any{
					"type": "RuntimeDefault",
				},
			},
			"containers": []any{
				map[string]any{
					"name":  "c",
					"image": "nginx",
					"securityContext": map[string]any{
						"allowPrivilegeEscalation": false,
						"capabilities": map[string]any{
							"drop": []any{"ALL"},
						},
					},
				},
			},
		},
	}}, Source: "test"}
}

func TestAnalyzeBaselineViolationDetected(t *testing.T) {
	out, err := Analyze([]loader.Resource{privilegedPod("bad")}, "test", "", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(out) != 1 || out[0].PolicyID != CheckIDBaseline {
		t.Fatalf("expected exactly one baseline finding, got %+v", out)
	}
	if !strings.Contains(out[0].Message, "baseline") {
		t.Errorf("expected message to mention baseline, got %q", out[0].Message)
	}
}

func TestAnalyzeRestrictedOnlyViolationDetected(t *testing.T) {
	out, err := Analyze([]loader.Resource{restrictedViolatingPod("mid")}, "test", "", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(out) != 1 || out[0].PolicyID != CheckIDRestricted {
		t.Fatalf("expected exactly one restricted finding (baseline should pass), got %+v", out)
	}
}

func TestAnalyzeFullyCompliantPodProducesNoFindings(t *testing.T) {
	out, err := Analyze([]loader.Resource{fullyRestrictedCompliantPod("good")}, "test", "", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no findings for a fully Restricted-compliant pod, got %+v", out)
	}
}

func TestAnalyzeDeploymentPodTemplate(t *testing.T) {
	dep := mustResource(t, map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "d", "namespace": "default"},
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": map[string]any{"app": "d"}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "d"}},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "c",
							"image": "nginx",
							"securityContext": map[string]any{
								"privileged": true,
							},
						},
					},
				},
			},
		},
	})
	out, err := Analyze([]loader.Resource{dep}, "test", "", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(out) != 1 || out[0].Resource.Kind != "Deployment" || out[0].Resource.Name != "d" {
		t.Fatalf("expected one finding attributed to the Deployment, got %+v", out)
	}
}

// TestAnalyzeOldClusterVersionAppliesOlderRules covers the version-pinning
// fix: pod-security-admission's own Restricted capabilities check only
// requires dropping ALL from 1.25 onward (an earlier revision applies
// before that) — evaluating an old cluster must use the rule that actually
// applied to it, not silently apply "latest" and produce a finding that
// wouldn't have fired against that cluster's real enforcement at the time.
func TestAnalyzeOldClusterVersionAppliesOlderRules(t *testing.T) {
	pod := restrictedViolatingPod("old")
	latest, err := Analyze([]loader.Resource{pod}, "test", "", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	old, err := Analyze([]loader.Resource{pod}, "test", "v1.20.0", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	// Both should still flag this pod (it's missing runAsNonRoot/seccomp
	// regardless of version) — the point is that Analyze doesn't error or
	// silently ignore the version, not that the exact reason text matches.
	if len(latest) != 1 || len(old) != 1 {
		t.Fatalf("expected exactly one finding at both versions, got latest=%+v old=%+v", latest, old)
	}
}

// TestAnalyzeConversionFailureWarns guards a real gap found by an
// adversarial audit: a resource that's a recognized pod-template-bearing
// kind but fails to convert (e.g. runAsUser written as a YAML string
// instead of an integer, a real mistake hand-written manifests can make)
// was silently skipped with zero diagnostic signal anywhere, even in -v
// mode — meaning PSS quietly checked nothing for that workload with no way
// to notice. It must now surface via the warn callback.
func TestAnalyzeConversionFailureWarns(t *testing.T) {
	bad := mustResource(t, map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "bad-type", "namespace": "default"},
		"spec": map[string]any{
			"securityContext": map[string]any{
				// runAsUser must be an integer; a string here fails
				// unstructured->typed conversion.
				"runAsUser": "1000",
			},
			"containers": []any{
				map[string]any{"name": "c", "image": "nginx"},
			},
		},
	})
	var warnings []string
	out, err := Analyze([]loader.Resource{bad}, "test", "", func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no findings for an unconvertible resource, got %+v", out)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected exactly one warning about the conversion failure, got %v", warnings)
	}
	if !strings.Contains(warnings[0], "bad-type") {
		t.Errorf("expected the warning to name the resource, got %q", warnings[0])
	}
}

func TestAnalyzeUnrelatedResourceIgnored(t *testing.T) {
	svc := mustResource(t, map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "s", "namespace": "default"},
	})
	out, err := Analyze([]loader.Resource{svc}, "test", "", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected a Service to be ignored, got %+v", out)
	}
}
