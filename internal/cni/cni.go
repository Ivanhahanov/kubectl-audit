// Package cni detects which CNI plugin a cluster runs, by the same
// well-known DaemonSet label signal internal/thirdparty uses for its
// Detected Components table, and flags a cluster whose CNI is known NOT to
// enforce NetworkPolicy at all (security-requirements.txt 5.1.4). This is
// a foundational gap: every netpol-analyzer.*/NetworkPolicy finding
// elsewhere in the same report assumes the CNI actually enforces whatever
// policy "covers" a workload — on a CNI that doesn't implement enforcement
// (plain Flannel with no policy add-on, for example), that coverage is
// purely cosmetic and every one of those findings is misleadingly
// optimistic.
package cni

import (
	"strings"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// CheckID is the finding/CIS-mapping ID for Analyze.
const CheckID = "cni-analyzer.no-policy-enforcement"

// knownCNI is one entry in the known-DaemonSet-label table below.
type knownCNI struct {
	name       string
	enforces   bool
	labelKey   string
	labelValue string
}

// knownCNIs is deliberately narrow: only CNIs this tool can confidently
// identify by a single well-known label, and whose NetworkPolicy
// enforcement behavior is documented and unambiguous. Anything not
// matching any entry here is left alone (see Analyze's doc comment) rather
// than guessed at.
var knownCNIs = []knownCNI{
	// Matches internal/thirdparty/components.yaml's Cilium/Calico entries
	// exactly, on purpose — same signal, same verified source.
	{name: "Cilium", enforces: true, labelKey: "k8s-app", labelValue: "cilium"},
	{name: "Calico", enforces: true, labelKey: "k8s-app", labelValue: "calico-node"},
	{name: "Weave Net", enforces: true, labelKey: "name", labelValue: "weave-net"},
	{name: "Antrea", enforces: true, labelKey: "app", labelValue: "antrea"},
	// Flannel implements pod networking only — no NetworkPolicy enforcement
	// of its own. The "Canal" combination (Flannel for networking + Calico
	// for policy) is common precisely because of this gap; a cluster
	// running both DaemonSets is correctly treated as enforcing (Calico's
	// entry above matches independently), not flagged.
	{name: "Flannel", enforces: false, labelKey: "app", labelValue: "flannel"},
	// The AWS VPC CNI (aws-node) historically shipped with no NetworkPolicy
	// enforcement; the optional network-policy-agent add-on is a separate
	// component this label alone can't confirm is running, so a cluster
	// with only aws-node is conservatively treated as non-enforcing.
	{name: "AWS VPC CNI (aws-node)", enforces: false, labelKey: "k8s-app", labelValue: "aws-node"},
}

// Analyze flags a cluster whose only identifiable CNI(s) are known
// non-enforcing ones. Deliberately conservative in both directions: a
// cluster where NO known CNI DaemonSet is recognized at all (an
// unrecognized name/label, a managed CNI this table doesn't know about
// yet, or a scan with insufficient RBAC/scope to see kube-system
// DaemonSets) produces no finding — silence, not a false "fail". A cluster
// where ANY enforcing CNI is recognized also produces no finding, even if
// a non-enforcing one is also present (the Canal case above) — enforcement
// only needs one component actually doing it.
func Analyze(resources []loader.Resource, source string) []findings.Finding {
	var enforcingNames, nonEnforcingNames []string
	var nonEnforcingSource string

	for _, r := range resources {
		gvk := r.GVK()
		if gvk.Group != "apps" || gvk.Kind != "DaemonSet" {
			continue
		}
		have := r.Object.GetLabels()
		for _, c := range knownCNIs {
			if have[c.labelKey] != c.labelValue {
				continue
			}
			if c.enforces {
				enforcingNames = append(enforcingNames, c.name)
			} else {
				nonEnforcingNames = append(nonEnforcingNames, c.name)
				nonEnforcingSource = r.Source
			}
		}
	}

	if len(enforcingNames) > 0 || len(nonEnforcingNames) == 0 {
		return nil
	}

	ref := findings.ResourceRef{Kind: "Cluster", Name: strings.Join(nonEnforcingNames, ", ")}
	return []findings.Finding{{
		ID:       findings.NewID(CheckID, ref),
		PolicyID: CheckID,
		Title:    "Detected CNI does not enforce NetworkPolicy",
		Severity: findings.SeverityHigh,
		Category: "network-security",
		Resource: ref,
		Message: "The only CNI(s) this scan could identify (" + strings.Join(nonEnforcingNames, ", ") + ") are " +
			"known not to enforce NetworkPolicy on their own — every NetworkPolicy coverage finding elsewhere " +
			"in this report (netpol-analyzer.*) describes what policy objects nominally exist, but none of it " +
			"is actually being enforced at the network layer, so every workload in this cluster is effectively " +
			"unrestricted regardless of what NetworkPolicy objects select it.",
		Remediation: "Either replace the CNI with one that enforces NetworkPolicy (Cilium, Calico, Antrea, " +
			"Weave Net), or add a policy-enforcement add-on to the existing CNI (e.g. pairing Flannel with " +
			"Calico — the \"Canal\" combination — or enabling the AWS VPC CNI's network-policy-agent add-on).",
		VerificationSteps: "1. This check only recognizes a small, high-confidence set of CNIs by a single " +
			"well-known DaemonSet label — confirm directly (`kubectl get daemonset -n kube-system` and check " +
			"what's actually running) rather than trusting detection alone, especially on a managed cluster " +
			"where the CNI might be customized or replaced. 2. If a policy-enforcement add-on is installed " +
			"alongside the detected CNI (the AWS network-policy-agent case above, for example) but isn't " +
			"identifiable by this check's label table, that's a false positive — verify before filing a ticket. " +
			"3. Every netpol-analyzer.*/NetworkPolicy finding in the same report should be treated as informational " +
			"only until this is resolved, not as an accurate picture of actual network restriction.",
		Source: nonEnforcingSource,
	}}
}
