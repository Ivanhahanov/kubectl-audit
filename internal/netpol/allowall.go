package netpol

import (
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// Check IDs for AnalyzeAllowAllModel below.
const (
	CheckIDIngressAllowAllRule = "netpol-analyzer.ingress-allow-all-rule"
	CheckIDEgressAllowAllRule  = "netpol-analyzer.egress-allow-all-rule"
)

// AnalyzeAllowAllModel flags workloads whose only ingress/egress "coverage"
// (per Analyze/AnalyzeReachability's meaning of the word) comes from a
// policy that still contains an unrestricted rule for that direction — an
// empty peer list, or an ipBlock of 0.0.0.0/0 (or ::/0) with no except.
// NetworkPolicy rules are additive across every policy selecting the same
// pod for the same direction (never intersected), so one such rule makes
// the workload's *effective* policy allow-all for that direction regardless
// of how many other, stricter policies also select it — the "allow-all
// masquerading as default-deny" model security-requirements.txt 4.6.1 calls
// out, distinct from Analyze/AnalyzeReachability's "no policy selects this
// workload at all" gap (a workload with zero coverage is out of scope here
// entirely — that's those checks' job, not this one's).
func AnalyzeAllowAllModel(resources []loader.Resource, source string) ([]findings.Finding, error) {
	nativeByNS := map[string][]*networkingv1.NetworkPolicy{}
	var workloads []loader.Resource

	for _, r := range resources {
		switch r.GVK() {
		case gvkNativeNetPol:
			var np networkingv1.NetworkPolicy
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(r.Object.Object, &np); err != nil {
				return nil, fmt.Errorf("converting NetworkPolicy %s/%s: %w", r.Namespace(), r.Name(), err)
			}
			nativeByNS[r.Namespace()] = append(nativeByNS[r.Namespace()], &np)
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
		wLabels := podTemplateLabels(w)
		ref := findings.ResourceRef{
			APIVersion: w.GVK().GroupVersion().String(),
			Kind:       w.GVK().Kind,
			Namespace:  ns,
			Name:       w.Name(),
		}
		if hasAllowAllRule(wLabels, nativeByNS[ns], "ingress") {
			out = append(out, allowAllFinding(w, ref, CheckIDIngressAllowAllRule, "ingress", ns))
		}
		if hasAllowAllRule(wLabels, nativeByNS[ns], "egress") {
			out = append(out, allowAllFinding(w, ref, CheckIDEgressAllowAllRule, "egress", ns))
		}
	}
	return out, nil
}

func hasAllowAllRule(workloadLabels map[string]string, policies []*networkingv1.NetworkPolicy, direction string) bool {
	for _, np := range policies {
		sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil || !sel.Matches(labels.Set(workloadLabels)) {
			continue
		}
		if direction == "ingress" {
			if !policyCoversIngress(np) {
				continue
			}
			for _, rule := range np.Spec.Ingress {
				if peerListAllowsEverything(rule.From) {
					return true
				}
			}
		} else {
			if !policyCoversEgress(np) {
				continue
			}
			for _, rule := range np.Spec.Egress {
				if peerListAllowsEverything(rule.To) {
					return true
				}
			}
		}
	}
	return false
}

// peerListAllowsEverything reports whether a NetworkPolicy rule's peer list
// matches every possible source/destination: an empty list (per the API's
// documented semantics, matches all), or an explicit 0.0.0.0/0 (or ::/0)
// ipBlock with no except carving anything back out.
func peerListAllowsEverything(peers []networkingv1.NetworkPolicyPeer) bool {
	if len(peers) == 0 {
		return true
	}
	for _, p := range peers {
		if p.PodSelector == nil && p.NamespaceSelector == nil && p.IPBlock != nil && isUnrestrictedIPBlock(p.IPBlock) {
			return true
		}
	}
	return false
}

func isUnrestrictedIPBlock(b *networkingv1.IPBlock) bool {
	if b.CIDR != "0.0.0.0/0" && b.CIDR != "::/0" {
		return false
	}
	return len(b.Except) == 0
}

func allowAllFinding(w loader.Resource, ref findings.ResourceRef, checkID, direction, ns string) findings.Finding {
	return findings.Finding{
		ID:       findings.NewID(checkID, ref),
		PolicyID: checkID,
		Title:    fmt.Sprintf("NetworkPolicy %s coverage is nominal — a covering rule still allows everything", direction),
		Severity: findings.SeverityMedium,
		Category: "network-security",
		Resource: ref,
		Message: fmt.Sprintf(
			"This workload is selected by a NetworkPolicy that restricts %s in namespace %q, but at least one of that policy's %s rules has no peer restriction (an empty peer list, or an ipBlock of 0.0.0.0/0 with no except) — since NetworkPolicy rules are additive across every policy selecting the same pod, this makes the workload's effective %s policy allow-all, not default-deny, regardless of any other stricter policy also selecting it.",
			direction, ns, direction, direction),
		Remediation: fmt.Sprintf("Replace the unrestricted %s rule with specific podSelector/namespaceSelector/ipBlock peers, or remove it if it was left over from an earlier allow-all baseline that a stricter policy was meant to replace.", direction),
		VerificationSteps: "1. This is a different gap from \"no NetworkPolicy selects this workload at all\" " +
			"(netpol-analyzer.no-network-policy-coverage / no-egress-restriction) — here a policy genuinely " +
			"exists and nominally restricts this direction, but one of its own rules still permits everything. " +
			"2. Check every NetworkPolicy selecting this workload for this direction, not just one — " +
			"NetworkPolicy rules are additive, so even a single allow-all rule anywhere in the set overrides " +
			"how strict any other policy looks. 3. Confirm this wasn't a deliberate transitional/bootstrap rule " +
			"(e.g. a staged rollout of a new default-deny baseline) before treating it as a hard finding.",
		Source: w.Source,
	}
}
