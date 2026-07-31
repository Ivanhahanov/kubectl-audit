// Package netpol checks whether workloads have applicable NetworkPolicy
// coverage. This can't be expressed as a single-object VAP/CEL policy:
// answering "is this Pod's traffic restricted" requires matching the
// workload's labels against every NetworkPolicy in its namespace, which is
// exactly the kind of cross-object reasoning the VAP engine can't do (see
// internal/rbac for the same rationale applied to RBAC).
//
// Coverage from the native Kubernetes NetworkPolicy API is checked
// precisely (podSelector + policyTypes matched against the workload's pod
// template labels). Cilium (CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy)
// and Calico (crd.projectcalico.org/v1 NetworkPolicy/GlobalNetworkPolicy)
// are only checked for *presence*, not simulated: their selector languages
// (endpointSelector, entities, services, ipBlocks, ...) are materially
// different from a label selector and reimplementing them is out of scope.
// Presence is used as a conservative "assume covered" signal so the
// analyzer doesn't produce false positives on clusters that rely on them
// instead of native NetworkPolicy.
package netpol

import (
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// CheckID is the finding/CIS-mapping ID for the coverage check.
const CheckID = "netpol-analyzer.no-network-policy-coverage"

var (
	gvkNativeNetPol            = schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"}
	gvkCiliumNetPol            = schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNetworkPolicy"}
	gvkCiliumClusterwideNetPol = schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumClusterwideNetworkPolicy"}
	gvkCalicoNetPol            = schema.GroupVersionKind{Group: "crd.projectcalico.org", Version: "v1", Kind: "NetworkPolicy"}
	gvkCalicoGlobalNetPol      = schema.GroupVersionKind{Group: "crd.projectcalico.org", Version: "v1", Kind: "GlobalNetworkPolicy"}
)

// Analyze checks every workload (Pod or a controller with a pod template)
// against the NetworkPolicy objects in its namespace and returns a finding
// for each one with no applicable coverage.
func Analyze(resources []loader.Resource, source string) ([]findings.Finding, error) {
	nativeByNS := map[string][]*networkingv1.NetworkPolicy{}
	ciliumNamespaces := map[string]bool{}
	calicoNamespaces := map[string]bool{}
	clusterWideCNI := false
	var workloads []loader.Resource

	for _, r := range resources {
		switch r.GVK() {
		case gvkNativeNetPol:
			var np networkingv1.NetworkPolicy
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(r.Object.Object, &np); err != nil {
				return nil, fmt.Errorf("converting NetworkPolicy %s/%s: %w", r.Namespace(), r.Name(), err)
			}
			nativeByNS[r.Namespace()] = append(nativeByNS[r.Namespace()], &np)
		case gvkCiliumNetPol:
			ciliumNamespaces[r.Namespace()] = true
		case gvkCalicoNetPol:
			calicoNamespaces[r.Namespace()] = true
		case gvkCiliumClusterwideNetPol, gvkCalicoGlobalNetPol:
			clusterWideCNI = true
		default:
			if isWorkloadGVK(r.GVK()) {
				workloads = append(workloads, r)
			}
		}
	}

	var out []findings.Finding
	for _, w := range workloads {
		ns := w.Namespace()
		if ns == "" {
			continue
		}
		if clusterWideCNI || ciliumNamespaces[ns] || calicoNamespaces[ns] {
			continue
		}
		if isCoveredByNativePolicy(podTemplateLabels(w), nativeByNS[ns]) {
			continue
		}

		ref := findings.ResourceRef{
			APIVersion: w.GVK().GroupVersion().String(),
			Kind:       w.GVK().Kind,
			Namespace:  ns,
			Name:       w.Name(),
		}
		out = append(out, findings.Finding{
			ID:       findings.NewID(CheckID, ref),
			PolicyID: CheckID,
			Title:    "Workload has no applicable NetworkPolicy",
			Severity: findings.SeverityHigh,
			Category: "network-security",
			CIS:      []string{"5.3.2"},
			Resource: ref,
			Message: fmt.Sprintf(
				"No NetworkPolicy in namespace %q selects this workload's pods (checked native Kubernetes NetworkPolicy; no Cilium/Calico policy was found for this namespace either): all ingress traffic is unrestricted.",
				ns),
			Remediation: "Add a NetworkPolicy (or namespace-wide default-deny policy) that selects this workload to restrict ingress/egress to what's actually needed.",
			Source:      w.Source,
		})
	}
	return out, nil
}

func isWorkloadGVK(gvk schema.GroupVersionKind) bool {
	switch gvk.Group {
	case "":
		return gvk.Kind == "Pod"
	case "apps":
		switch gvk.Kind {
		case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet":
			return true
		}
	case "batch":
		switch gvk.Kind {
		case "Job", "CronJob":
			return true
		}
	}
	return false
}

// podTemplateLabels extracts the labels of the Pods a workload produces:
// its own labels for a bare Pod, or the nested pod template's labels for a
// controller (accounting for CronJob's extra jobTemplate nesting).
func podTemplateLabels(r loader.Resource) map[string]string {
	if r.GVK().Kind == "Pod" {
		return r.Object.GetLabels()
	}

	path := []string{"spec", "template", "metadata", "labels"}
	if r.GVK().Kind == "CronJob" {
		path = []string{"spec", "jobTemplate", "spec", "template", "metadata", "labels"}
	}
	labelMap, found, _ := unstructured.NestedStringMap(r.Object.Object, path...)
	if !found {
		return map[string]string{}
	}
	return labelMap
}

// isCoveredByNativePolicy reports whether any policy's podSelector matches
// the workload's labels and the policy actually restricts Ingress (a
// PolicyType list that omits Ingress, e.g. an egress-only policy, doesn't
// count). An empty PolicyTypes list defaults to at least Ingress per the
// NetworkPolicy API's documented defaulting behavior.
func isCoveredByNativePolicy(workloadLabels map[string]string, policies []*networkingv1.NetworkPolicy) bool {
	for _, np := range policies {
		if !policyCoversIngress(np) {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil {
			continue
		}
		if sel.Matches(labels.Set(workloadLabels)) {
			return true
		}
	}
	return false
}

func policyCoversIngress(np *networkingv1.NetworkPolicy) bool {
	if len(np.Spec.PolicyTypes) == 0 {
		return true
	}
	for _, t := range np.Spec.PolicyTypes {
		if t == networkingv1.PolicyTypeIngress {
			return true
		}
	}
	return false
}
