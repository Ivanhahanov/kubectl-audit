package controlplane

import (
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// PSACheckID is the finding/CIS-mapping ID for checkNamespacePSAEnforcement.
// Deliberately NOT under CheckIDPrefix/VAPCheckIDPrefix: unlike the other
// control-plane checks, this one is still meaningful when the apiserver
// isn't observed at all (namespace labels are visible either way), so it
// must not be swept into NOT_APPLICABLE by compliance.OverrideUnobserved
// just because a managed control plane hides the apiserver Pod.
const PSACheckID = "psa-analyzer.no-active-enforcement"

// checkNamespacePSAEnforcement flags namespaces with no active Pod Security
// Admission enforcement (CIS 5.2.1).
//
// PSA can be turned on for a namespace two ways: a
// pod-security.kubernetes.io/enforce label on the Namespace itself, or a
// cluster-wide default configured via kube-apiserver's
// --admission-control-config-file (an AdmissionConfiguration/
// PodSecurityConfiguration) — which needs no per-namespace label at all. The
// file's content lives on the control-plane node, not the API, so its
// content can't be confirmed the way the flag's mere presence can; when the
// flag is set, this check backs off entirely rather than false-failing every
// namespace on a cluster that's actually enforcing PSA cluster-wide. That
// trades a false negative (missing a file set for some unrelated plugin)
// for avoiding a systematic false positive across every namespace on a
// common, valid configuration this tool otherwise has no way to see.
func checkNamespacePSAEnforcement(resources []loader.Resource, apiserverFlags flags, apiserverObserved bool, source string) []findings.Finding {
	if apiserverObserved && apiserverFlags.isSet("admission-control-config-file") {
		return nil
	}

	var out []findings.Finding
	for _, r := range resources {
		gvk := r.GVK()
		if gvk.Group != "" || gvk.Kind != "Namespace" {
			continue
		}
		if _, ok := r.Object.GetLabels()["pod-security.kubernetes.io/enforce"]; ok {
			continue
		}
		ref := findings.ResourceRef{APIVersion: "v1", Kind: "Namespace", Name: r.Name()}
		out = append(out, findings.Finding{
			ID:       findings.NewID(PSACheckID, ref),
			PolicyID: PSACheckID,
			Title:    "Namespace has no active Pod Security Admission enforcement",
			Severity: findings.SeverityMedium,
			Category: "workload-security",
			CIS:      []string{"5.2.1"},
			Resource: ref,
			Message: "Namespace does not set the pod-security.kubernetes.io/enforce label, and no kube-apiserver " +
				"--admission-control-config-file was observed that might configure cluster-wide PSA defaults instead " +
				"— on unmodified Kubernetes defaults, this means no Pod Security Standards level is actively enforced " +
				"for this namespace.",
			Remediation: "Set the pod-security.kubernetes.io/enforce label on the namespace (baseline or restricted), " +
				"or configure cluster-wide PodSecurityConfiguration defaults via --admission-control-config-file.",
			VerificationSteps: "1. Run `kubectl get ns <name> -o jsonpath='{.metadata.labels}'` yourself to " +
				"confirm the enforce label is genuinely absent (not just missing from what this scan happened " +
				"to load). 2. Ask whether this namespace is expected to be short-lived/system-internal " +
				"(e.g. a CI scratch namespace) where PSA enforcement may be deliberately skipped — that's a " +
				"legitimate reason to accept the risk, not a false positive, so record it as such rather than " +
				"dismissing the finding outright. 3. If the cluster IS using --admission-control-config-file " +
				"but this tool couldn't see the apiserver Pod at all (a managed control plane), this finding " +
				"could be a false positive — check the Scope section of the report for whether control-plane " +
				"objects were observed in this scan before trusting it.",
			Source: r.Source,
		})
	}
	return out
}
