package netpol

import (
	"fmt"
	"net"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// CheckIDEgressToMetadataAllowed is the finding/CIS-mapping ID for
// AnalyzeMetadataEgress.
const CheckIDEgressToMetadataAllowed = "netpol-analyzer.egress-to-metadata-allowed"

// cloudMetadataIP is the well-known cloud-provider instance metadata
// address (AWS/GCP/Azure/most others) — commonly the path from an
// SSRF/RCE in a workload to that workload's node/instance IAM credentials
// (security-requirements.txt 5.1.2/5.2.2).
var cloudMetadataIP = net.ParseIP("169.254.169.254")

// AnalyzeMetadataEgress flags workloads whose egress-restricting
// NetworkPolicy still permits reaching the cloud metadata endpoint.
// Complementary to AnalyzeReachability's CheckIDNoEgressRestriction: that
// check flags workloads with NO egress restriction at all; this one only
// evaluates workloads that DO have at least one egress-restricting policy
// selecting them, and checks whether its rules still leave the metadata
// endpoint reachable. A workload with zero egress coverage is skipped here
// entirely (CheckIDNoEgressRestriction's job, not this one's) to avoid
// reporting the same underlying gap twice under two policy IDs.
func AnalyzeMetadataEgress(resources []loader.Resource, source string) ([]findings.Finding, error) {
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
		// Same "assume covered" conservative stance as coverage.go/
		// reachability.go: Cilium/Calico's egress rule languages aren't
		// simulated here, so a namespace using either is skipped rather
		// than risking a false positive this analyzer can't actually back up.
		if clusterWideCNI || ciliumNamespaces[ns] || calicoNamespaces[ns] {
			continue
		}
		applicable := egressPoliciesCovering(podTemplateLabels(w), nativeByNS[ns])
		if len(applicable) == 0 {
			continue
		}
		if !anyRuleAllowsMetadata(applicable) {
			continue
		}

		ref := findings.ResourceRef{
			APIVersion: w.GVK().GroupVersion().String(),
			Kind:       w.GVK().Kind,
			Namespace:  ns,
			Name:       w.Name(),
		}
		out = append(out, findings.Finding{
			ID:       findings.NewID(CheckIDEgressToMetadataAllowed, ref),
			PolicyID: CheckIDEgressToMetadataAllowed,
			Title:    "Egress-restricting NetworkPolicy still allows reaching the cloud metadata endpoint",
			Severity: findings.SeverityHigh,
			Category: "network-security",
			Resource: ref,
			Message: fmt.Sprintf(
				"This workload has an egress-restricting NetworkPolicy in namespace %q, but at least one of its "+
					"egress rules still permits reaching 169.254.169.254 (the cloud provider metadata endpoint) — "+
					"an SSRF or RCE in this workload could reach it and retrieve node/instance IAM credentials.",
				ns),
			Remediation: "Add an explicit except: [\"169.254.169.254/32\"] to any egress rule's ipBlock that " +
				"would otherwise cover it (including an empty \"to: []\", which matches every destination), or " +
				"scope the rule's ipBlock/selector away from it entirely.",
			VerificationSteps: "1. Re-read the workload's applicable NetworkPolicy egress rules directly — this " +
				"check flags a rule whose ipBlock CIDR contains 169.254.169.254 with no except excluding it, or a " +
				"rule with an empty \"to\" (matches everywhere). 2. Confirm the cluster actually runs on a cloud " +
				"provider whose metadata endpoint lives at 169.254.169.254 (AWS/GCP/Azure/most others) — a " +
				"self-hosted/bare-metal cluster with nothing listening there is a much lower-priority finding. " +
				"3. Check whether the workload's own cloud IAM/instance-profile grants meaningful permissions at " +
				"all — a reachable metadata endpoint on a workload with no attached credentials is far less " +
				"severe than one with a privileged instance role.",
			Source: w.Source,
		})
	}
	return out, nil
}

func egressPoliciesCovering(workloadLabels map[string]string, policies []*networkingv1.NetworkPolicy) []*networkingv1.NetworkPolicy {
	var out []*networkingv1.NetworkPolicy
	for _, np := range policies {
		if !policyCoversEgress(np) {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil {
			continue
		}
		if sel.Matches(labels.Set(workloadLabels)) {
			out = append(out, np)
		}
	}
	return out
}

func anyRuleAllowsMetadata(policies []*networkingv1.NetworkPolicy) bool {
	for _, np := range policies {
		for _, rule := range np.Spec.Egress {
			if egressRuleAllowsMetadata(rule) {
				return true
			}
		}
	}
	return false
}

func egressRuleAllowsMetadata(rule networkingv1.NetworkPolicyEgressRule) bool {
	if len(rule.To) == 0 {
		return true
	}
	for _, peer := range rule.To {
		if peer.IPBlock == nil {
			continue
		}
		_, ipnet, err := net.ParseCIDR(peer.IPBlock.CIDR)
		if err != nil || !ipnet.Contains(cloudMetadataIP) {
			continue
		}
		if !exceptExcludesMetadata(peer.IPBlock.Except) {
			return true
		}
	}
	return false
}

func exceptExcludesMetadata(except []string) bool {
	for _, e := range except {
		_, exceptNet, err := net.ParseCIDR(e)
		if err == nil && exceptNet.Contains(cloudMetadataIP) {
			return true
		}
	}
	return false
}
