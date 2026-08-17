package suppress_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/suppress"
)

func daemonSetResource(name string, labels map[string]string) loader.Resource {
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "DaemonSet",
		"metadata":   map[string]any{"name": name, "namespace": "kube-system"},
	}
	if labels != nil {
		metadata := obj["metadata"].(map[string]any)
		labelsAny := make(map[string]any, len(labels))
		for k, v := range labels {
			labelsAny[k] = v
		}
		metadata["labels"] = labelsAny
	}
	return loader.Resource{Object: &unstructured.Unstructured{Object: obj}}
}

func TestBuiltinRules_CiliumAgent_KnownViolationsSuppressed(t *testing.T) {
	cilium := daemonSetResource("cilium", map[string]string{"k8s-app": "cilium"})
	all := []findings.Finding{
		{PolicyID: "workload.no-privileged-containers", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "cilium"}},
		{PolicyID: "workload.no-host-namespaces", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "cilium"}},
		{PolicyID: "pss-analyzer.baseline", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "cilium"}},
		// Not in the known-violation set — must survive.
		{PolicyID: "workload.no-latest-tag", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "cilium"}},
		{PolicyID: "workload.resource-limits-required", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "cilium"}},
	}

	idx := suppress.BuildLabelIndex([]loader.Resource{cilium})
	kept, suppressedFindings := suppress.Apply(all, suppress.BuiltinRules(), idx)

	if len(suppressedFindings) != 3 {
		t.Fatalf("expected exactly the 3 known-violation findings suppressed, got %d: %+v", len(suppressedFindings), suppressedFindings)
	}
	if len(kept) != 2 {
		t.Fatalf("expected the 2 unrelated findings (image tag, resource limits) to survive, got %d: %+v", len(kept), kept)
	}
	for _, f := range kept {
		if f.PolicyID != "workload.no-latest-tag" && f.PolicyID != "workload.resource-limits-required" {
			t.Errorf("unexpected finding survived suppression: %s", f.PolicyID)
		}
	}
}

func TestBuiltinRules_CiliumOperator_NotCovered(t *testing.T) {
	// cilium-operator has different labels (io.cilium/app: operator, not
	// k8s-app: cilium) — an unexpectedly-privileged operator must still be
	// flagged, since the official chart never runs it privileged.
	operator := daemonSetResource("cilium-operator", map[string]string{"io.cilium/app": "operator", "name": "cilium-operator"})
	all := []findings.Finding{
		{PolicyID: "workload.no-privileged-containers", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "cilium-operator"}},
	}

	idx := suppress.BuildLabelIndex([]loader.Resource{operator})
	kept, suppressedFindings := suppress.Apply(all, suppress.BuiltinRules(), idx)

	if len(suppressedFindings) != 0 {
		t.Errorf("expected cilium-operator's finding to NOT be covered by the cilium-agent exception, got %+v", suppressedFindings)
	}
	if len(kept) != 1 {
		t.Errorf("expected the finding to survive, got %+v", kept)
	}
}

func TestBuiltinRules_UnrelatedWorkload_NotAffected(t *testing.T) {
	// A workload with hostNetwork but none of the known labels must not be
	// affected — this is the whole point of label-based (not
	// namespace-based) matching.
	unrelated := daemonSetResource("some-app", map[string]string{"app": "some-app"})
	all := []findings.Finding{
		{PolicyID: "workload.no-host-namespaces", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "some-app"}},
	}

	idx := suppress.BuildLabelIndex([]loader.Resource{unrelated})
	kept, suppressedFindings := suppress.Apply(all, suppress.BuiltinRules(), idx)

	if len(suppressedFindings) != 0 {
		t.Errorf("expected an unrelated workload's finding to not be suppressed, got %+v", suppressedFindings)
	}
	if len(kept) != 1 {
		t.Errorf("expected the finding to survive, got %+v", kept)
	}
}

func TestBuiltinRules_NodeExporter_CapabilitiesNotSuppressed(t *testing.T) {
	// node-exporter runs unprivileged with no added capabilities — unlike
	// Cilium, workload.no-privileged-containers/drop-all-capabilities are
	// deliberately NOT in its rule, so an unexpected capability finding
	// must still surface.
	nodeExporter := daemonSetResource("node-exporter", map[string]string{"app.kubernetes.io/name": "prometheus-node-exporter"})
	all := []findings.Finding{
		{PolicyID: "workload.no-host-namespaces", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "node-exporter"}},
		{PolicyID: "workload.drop-all-capabilities", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "node-exporter"}},
	}

	idx := suppress.BuildLabelIndex([]loader.Resource{nodeExporter})
	kept, suppressedFindings := suppress.Apply(all, suppress.BuiltinRules(), idx)

	if len(suppressedFindings) != 1 || suppressedFindings[0].Finding.PolicyID != "workload.no-host-namespaces" {
		t.Fatalf("expected only no-host-namespaces suppressed, got %+v", suppressedFindings)
	}
	if len(kept) != 1 || kept[0].PolicyID != "workload.drop-all-capabilities" {
		t.Fatalf("expected drop-all-capabilities to survive (node-exporter isn't expected to need capabilities), got %+v", kept)
	}
}

func TestBuiltinRules_Falco_HostNamespacesNotSuppressed(t *testing.T) {
	// Falco doesn't use hostNetwork/hostPID (it observes the host via
	// mounts, not host namespaces) — an unexpected host-namespace finding
	// must still surface.
	falco := daemonSetResource("falco", map[string]string{"app.kubernetes.io/name": "falco"})
	all := []findings.Finding{
		{PolicyID: "workload.no-privileged-containers", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "falco"}},
		{PolicyID: "workload.no-hostpath-volumes", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "falco"}},
		{PolicyID: "workload.no-host-namespaces", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "falco"}},
	}

	idx := suppress.BuildLabelIndex([]loader.Resource{falco})
	kept, suppressedFindings := suppress.Apply(all, suppress.BuiltinRules(), idx)

	if len(suppressedFindings) != 2 {
		t.Fatalf("expected exactly 2 findings suppressed (privileged, hostpath), got %d: %+v", len(suppressedFindings), suppressedFindings)
	}
	if len(kept) != 1 || kept[0].PolicyID != "workload.no-host-namespaces" {
		t.Fatalf("expected no-host-namespaces to survive (Falco doesn't use host namespaces), got %+v", kept)
	}
}

func TestBuiltinRules_TetragonAgent_KnownViolationsSuppressed(t *testing.T) {
	agent := daemonSetResource("tetragon", map[string]string{"app.kubernetes.io/name": "tetragon"})
	all := []findings.Finding{
		{PolicyID: "workload.no-privileged-containers", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "tetragon"}},
		{PolicyID: "workload.no-host-namespaces", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "tetragon"}},
		{PolicyID: "pss-analyzer.restricted", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "tetragon"}},
	}

	idx := suppress.BuildLabelIndex([]loader.Resource{agent})
	kept, suppressedFindings := suppress.Apply(all, suppress.BuiltinRules(), idx)

	if len(suppressedFindings) != 2 {
		t.Fatalf("expected exactly 2 findings suppressed (privileged, host-namespaces), got %d: %+v", len(suppressedFindings), suppressedFindings)
	}
	if len(kept) != 1 || kept[0].PolicyID != "pss-analyzer.restricted" {
		t.Fatalf("expected pss-analyzer.restricted to survive (no seccomp profile is an independent gap), got %+v", kept)
	}
}

func TestBuiltinRules_TetragonOperator_NotCovered(t *testing.T) {
	// tetragon-operator has a different label (app.kubernetes.io/name:
	// tetragon-operator, not tetragon) and runs unprivileged — an
	// unexpectedly-privileged operator must still be flagged.
	operator := daemonSetResource("tetragon-operator", map[string]string{"app.kubernetes.io/name": "tetragon-operator"})
	all := []findings.Finding{
		{PolicyID: "workload.no-privileged-containers", Resource: findings.ResourceRef{Kind: "DaemonSet", Namespace: "kube-system", Name: "tetragon-operator"}},
	}

	idx := suppress.BuildLabelIndex([]loader.Resource{operator})
	kept, suppressedFindings := suppress.Apply(all, suppress.BuiltinRules(), idx)

	if len(suppressedFindings) != 0 {
		t.Errorf("expected tetragon-operator's finding to NOT be covered by the tetragon-agent exception, got %+v", suppressedFindings)
	}
	if len(kept) != 1 {
		t.Errorf("expected the finding to survive, got %+v", kept)
	}
}
