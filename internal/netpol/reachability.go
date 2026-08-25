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

// Check IDs for the two reachability signals below. Complementary to
// Analyze's ingress-coverage check (CheckID): together they answer "where
// can this workload's traffic actually go" — not a full connectivity-graph
// simulation (see the package doc comment for why that's out of scope for
// Cilium/Calico), just the two concrete, unambiguous native-NetworkPolicy
// gaps that are easiest to miss reading YAML by eye.
const (
	// CheckIDBroadNamespaceSelector fires on a namespaceSelector set
	// without a podSelector in the same peer entry: per the NetworkPolicy
	// API, that matches every pod in the selected namespace(s), not just
	// specific ones — a well-known, easy-to-miss surprise (reviewers often
	// assume namespaceSelector narrows scope down to specific pods too).
	CheckIDBroadNamespaceSelector = "netpol-analyzer.broad-namespace-selector-rule"
	// CheckIDNoEgressRestriction is the egress mirror of Analyze's
	// ingress-coverage check: a workload with no NetworkPolicy actually
	// restricting Egress can reach any destination outbound — including
	// the Kubernetes API server itself, other namespaces, and (network
	// layer permitting) the internet.
	CheckIDNoEgressRestriction = "netpol-analyzer.no-egress-restriction"
)

// nativePolicy pairs a parsed NetworkPolicy with the loader.Resource it came
// from, so findings can cite the source manifest/namespace.
type nativePolicy struct {
	np  *networkingv1.NetworkPolicy
	res loader.Resource
}

// AnalyzeReachability runs native-NetworkPolicy reachability checks
// complementary to Analyze. Deliberately native-only for the same reason
// Analyze's coverage check only checks presence (not simulation) for
// Cilium/Calico: their selector languages don't decompose into
// podSelector/namespaceSelector the way this analysis needs. A namespace
// using Cilium/Calico for egress control is conservatively skipped here too
// (same "assume covered" stance as Analyze), so this never produces a false
// positive just because the cluster doesn't use native NetworkPolicy.
func AnalyzeReachability(resources []loader.Resource, source string) ([]findings.Finding, error) {
	var policies []nativePolicy
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
			policies = append(policies, nativePolicy{np: &np, res: r})
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
	out = append(out, checkBroadNamespaceSelectors(policies)...)
	out = append(out, checkNoEgressRestriction(workloads, nativeByNS, ciliumNamespaces, calicoNamespaces, clusterWideCNI)...)
	return out, nil
}

func checkBroadNamespaceSelectors(policies []nativePolicy) []findings.Finding {
	var out []findings.Finding
	for _, p := range policies {
		for ruleIdx, rule := range p.np.Spec.Ingress {
			for peerIdx, peer := range rule.From {
				if f, ok := broadPeerFinding(p, "ingress", ruleIdx, peerIdx, peer); ok {
					out = append(out, f)
				}
			}
		}
		for ruleIdx, rule := range p.np.Spec.Egress {
			for peerIdx, peer := range rule.To {
				if f, ok := broadPeerFinding(p, "egress", ruleIdx, peerIdx, peer); ok {
					out = append(out, f)
				}
			}
		}
	}
	return out
}

func broadPeerFinding(p nativePolicy, direction string, ruleIdx, peerIdx int, peer networkingv1.NetworkPolicyPeer) (findings.Finding, bool) {
	if peer.NamespaceSelector == nil || peer.PodSelector != nil {
		return findings.Finding{}, false
	}
	scope := "every namespace matching its selector"
	if len(peer.NamespaceSelector.MatchLabels) == 0 && len(peer.NamespaceSelector.MatchExpressions) == 0 {
		scope = "every namespace in the cluster (an empty namespaceSelector matches all namespaces)"
	}
	ref := findings.ResourceRef{
		APIVersion: p.res.GVK().GroupVersion().String(),
		Kind:       p.res.GVK().Kind,
		Namespace:  p.res.Namespace(),
		Name:       p.res.Name(),
	}
	discriminator := fmt.Sprintf("%s|%d|%d", direction, ruleIdx, peerIdx)
	return findings.Finding{
		ID:       findings.NewID(CheckIDBroadNamespaceSelector, ref, discriminator),
		PolicyID: CheckIDBroadNamespaceSelector,
		Title:    "NetworkPolicy rule sets namespaceSelector without podSelector",
		Severity: findings.SeverityMedium,
		Category: "network-security",
		Resource: ref,
		Message: fmt.Sprintf(
			"%s rule #%d, peer #%d sets namespaceSelector without a podSelector — this matches %s, not just specific pods within it.",
			directionLabel(direction), ruleIdx+1, peerIdx+1, scope),
		Remediation: "Add a podSelector alongside namespaceSelector to scope the rule to specific pods, or confirm that allowing every pod in the matched namespace(s) is actually intended.",
		VerificationSteps: "1. Re-read the actual peer rule (see the rule/peer numbers in the Message) in the " +
			"source YAML to confirm the omission is real. 2. Check whether matching every pod in the selected " +
			"namespace(s) was the actual intent (e.g. an ingress-controller namespace where every pod IS the " +
			"trusted peer) vs. an accidental over-broad rule — the fix differs: add a podSelector, or just " +
			"document the intent if it's already correct. 3. An empty namespaceSelector (matches ALL " +
			"namespaces in the cluster, called out explicitly in the Message when it applies) is materially " +
			"more severe than one scoped to a labeled subset — prioritize accordingly.",
		Source: p.res.Source,
	}, true
}

func directionLabel(direction string) string {
	if direction == "ingress" {
		return "Ingress"
	}
	return "Egress"
}

func checkNoEgressRestriction(workloads []loader.Resource, nativeByNS map[string][]*networkingv1.NetworkPolicy, ciliumNamespaces, calicoNamespaces map[string]bool, clusterWideCNI bool) []findings.Finding {
	var out []findings.Finding
	for _, w := range workloads {
		ns := w.Namespace()
		if ns == "" {
			continue
		}
		if clusterWideCNI || ciliumNamespaces[ns] || calicoNamespaces[ns] {
			continue
		}
		if isCoveredByEgressPolicy(podTemplateLabels(w), nativeByNS[ns]) {
			continue
		}

		ref := findings.ResourceRef{
			APIVersion: w.GVK().GroupVersion().String(),
			Kind:       w.GVK().Kind,
			Namespace:  ns,
			Name:       w.Name(),
		}
		out = append(out, findings.Finding{
			ID:       findings.NewID(CheckIDNoEgressRestriction, ref),
			PolicyID: CheckIDNoEgressRestriction,
			Title:    "Workload has no egress-restricting NetworkPolicy",
			Severity: findings.SeverityMedium,
			Category: "network-security",
			Resource: ref,
			Message: fmt.Sprintf(
				"No NetworkPolicy in namespace %q restricts this workload's egress traffic (checked native Kubernetes NetworkPolicy; no Cilium/Calico policy was found for this namespace either): it can reach any destination outbound, including the Kubernetes API server, other namespaces, and the internet.",
				ns),
			Remediation: "Add a NetworkPolicy with policyTypes: [Egress] selecting this workload, restricting outbound traffic to only the destinations it actually needs.",
			VerificationSteps: "1. Check the Detected Components table for Cilium/Calico egress control that " +
				"this check couldn't observe (same caveat as the ingress-coverage check). 2. Assess actual " +
				"blast radius: unrestricted egress from a compromised pod is most dangerous for internet-" +
				"facing or high-privilege workloads (data exfiltration, C2 callback) — prioritize those over " +
				"genuinely internal, low-value pods when sequencing remediation. 3. If cluster access is " +
				"available, confirm directly: from this workload, attempt to reach an unexpected destination " +
				"(an external IP, or another namespace's Service) to verify egress really is unrestricted.",
			Source: w.Source,
		})
	}
	return out
}

// isCoveredByEgressPolicy mirrors isCoveredByNativePolicy for Egress: does
// any policy selecting this workload actually restrict egress. An
// Egress-type policy with zero rules denies all egress (that's coverage,
// just very strict); one with rules restricts to those rules.
func isCoveredByEgressPolicy(workloadLabels map[string]string, policies []*networkingv1.NetworkPolicy) bool {
	for _, np := range policies {
		if !policyCoversEgress(np) {
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

// policyCoversEgress replicates the NetworkPolicy API's documented
// PolicyTypes defaulting: an explicit list is taken as-is, but when
// PolicyTypes is unset, Egress is only implied if the policy actually
// declares Egress rules (unlike Ingress, which is always implied) — see
// https://pkg.go.dev/k8s.io/api/networking/v1#NetworkPolicySpec.
func policyCoversEgress(np *networkingv1.NetworkPolicy) bool {
	if len(np.Spec.PolicyTypes) > 0 {
		for _, t := range np.Spec.PolicyTypes {
			if t == networkingv1.PolicyTypeEgress {
				return true
			}
		}
		return false
	}
	return len(np.Spec.Egress) > 0
}
