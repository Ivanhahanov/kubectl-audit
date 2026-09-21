package cni_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/ivanhahanov/kubectl-audit/internal/cni"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

func daemonSet(name string, labels map[string]string) loader.Resource {
	l := map[string]any{}
	for k, v := range labels {
		l[k] = v
	}
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "DaemonSet",
		"metadata": map[string]any{
			"name":      name,
			"namespace": "kube-system",
			"labels":    l,
		},
	}
	return loader.Resource{Object: &unstructured.Unstructured{Object: obj}, Source: "test"}
}

func TestFlannelOnlyFlagged(t *testing.T) {
	found := cni.Analyze([]loader.Resource{
		daemonSet("kube-flannel-ds", map[string]string{"app": "flannel"}),
	}, "test")
	if len(found) != 1 || found[0].PolicyID != cni.CheckID {
		t.Fatalf("expected one no-policy-enforcement finding for Flannel-only, got %+v", found)
	}
}

func TestCiliumOnlyNotFlagged(t *testing.T) {
	found := cni.Analyze([]loader.Resource{
		daemonSet("cilium", map[string]string{"k8s-app": "cilium"}),
	}, "test")
	if len(found) != 0 {
		t.Errorf("expected no finding when Cilium is detected, got %+v", found)
	}
}

func TestCanalCombinationNotFlagged(t *testing.T) {
	found := cni.Analyze([]loader.Resource{
		daemonSet("kube-flannel-ds", map[string]string{"app": "flannel"}),
		daemonSet("calico-node", map[string]string{"k8s-app": "calico-node"}),
	}, "test")
	if len(found) != 0 {
		t.Errorf("expected no finding for Flannel+Calico (Canal) — Calico provides enforcement, got %+v", found)
	}
}

func TestUnrecognizedCNIProducesNoFinding(t *testing.T) {
	found := cni.Analyze([]loader.Resource{
		daemonSet("some-custom-cni", map[string]string{"app": "totally-custom"}),
	}, "test")
	if len(found) != 0 {
		t.Errorf("expected silence (not a false fail) when no known CNI label matches, got %+v", found)
	}
}

func TestNoDaemonSetsAtAllProducesNoFinding(t *testing.T) {
	found := cni.Analyze(nil, "test")
	if len(found) != 0 {
		t.Errorf("expected no finding with zero DaemonSets observed, got %+v", found)
	}
}

func TestAWSVPCCNIOnlyFlagged(t *testing.T) {
	found := cni.Analyze([]loader.Resource{
		daemonSet("aws-node", map[string]string{"k8s-app": "aws-node"}),
	}, "test")
	if len(found) != 1 || found[0].PolicyID != cni.CheckID {
		t.Fatalf("expected one no-policy-enforcement finding for aws-node-only, got %+v", found)
	}
}
