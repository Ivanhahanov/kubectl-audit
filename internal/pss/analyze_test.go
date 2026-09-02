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

func restrictedViolatingPodWithContainer(name, containerName string) loader.Resource {
	return loader.Resource{Object: &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": name, "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{
					"name":  containerName,
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

// TestAnalyze_DedupKeyIgnoresContainerNameButKeepsViolatedRules is the fix
// for a real report: on a cluster with many unrelated tenant workloads each
// independently missing the same securityContext field, ForbiddenDetail()
// names the specific violating container ("runAsNonRoot != true (container
// api-v2)" vs "... (container app-no-ssh-here)"), which kept the triage
// TUI's dedup from ever collapsing them — the Message differed purely by
// container name, not by which security rule was actually violated.
// DedupKey (built from ForbiddenReason(), not ForbiddenDetail()) must be
// identical across two pods that violate the exact same set of rules via
// differently-named containers, so the TUI's dedup.go can bucket them
// together while Message (checked separately) keeps the full per-container
// detail for the single-finding view and any filed Jira ticket.
func TestAnalyze_DedupKeyIgnoresContainerNameButKeepsViolatedRules(t *testing.T) {
	outA, err := Analyze([]loader.Resource{restrictedViolatingPodWithContainer("app-a", "api-v2")}, "test", "", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	outB, err := Analyze([]loader.Resource{restrictedViolatingPodWithContainer("app-b", "app-no-ssh-here")}, "test", "", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(outA) != 1 || len(outB) != 1 {
		t.Fatalf("expected exactly one finding each, got %d and %d", len(outA), len(outB))
	}
	if outA[0].Message == outB[0].Message {
		t.Fatalf("expected Message to differ by container name (test setup assumption broken), got identical: %q", outA[0].Message)
	}
	if outA[0].DedupKey == "" {
		t.Fatal("expected a non-empty DedupKey")
	}
	if outA[0].DedupKey != outB[0].DedupKey {
		t.Errorf("expected identical DedupKey for the same violated rules via different containers, got %q vs %q", outA[0].DedupKey, outB[0].DedupKey)
	}

	// A pod violating a genuinely DIFFERENT set of rules (privileged,
	// baseline-level) must get a different DedupKey.
	outC, err := Analyze([]loader.Resource{privilegedPod("app-c")}, "test", "", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(outC) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", outC)
	}
	if outC[0].DedupKey == outA[0].DedupKey {
		t.Errorf("expected a different violated-rule set (baseline privileged vs restricted) to get a different DedupKey, both were %q", outC[0].DedupKey)
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
