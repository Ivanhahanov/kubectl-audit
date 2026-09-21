// Package istio checks whether workloads in an Istio-injected namespace
// have applicable AuthorizationPolicy coverage. This can't be a
// single-object VAP/CEL policy: answering "is this workload's traffic
// authorized" requires matching the workload's labels against every
// AuthorizationPolicy in its namespace, the same cross-object reasoning
// internal/netpol does for NetworkPolicy coverage. The existing
// policies/thirdparty/istio/*.yaml VAP checks only evaluate the *content*
// of an AuthorizationPolicy that already exists (e.g. "does this ALLOW
// rule restrict its source") — this package answers the complementary
// question those can't: does one exist for this workload at all.
package istio

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// CheckID is the finding/CIS-mapping ID for AnalyzeAuthorizationCoverage.
const CheckID = "istio-analyzer.no-authorization-policy-coverage"

// isAuthzPolicyGVK matches both apiVersions Istio has ever shipped for
// this Kind (v1 and v1beta1 are the same Go type — verified 2026-08
// against istio/api's security/v1 generated aliases, same fact the
// policies/thirdparty/istio/*.yaml VAP checks rely on), so Group+Kind is
// compared without pinning a Version.
func isAuthzPolicyGVK(gvk schema.GroupVersionKind) bool {
	return gvk.Group == "security.istio.io" && gvk.Kind == "AuthorizationPolicy"
}

// meshEnabled reports whether a Namespace opts into Istio sidecar
// injection via either documented convention: the classic
// istio-injection=enabled label, or revisioned injection's istio.io/rev
// label (any value — the specific revision name doesn't matter here).
// Workloads in a namespace matching neither are not part of the mesh as
// far as this check can tell, and are skipped entirely rather than risking
// a false positive on a cluster that only partially adopted Istio.
func meshEnabled(ns loader.Resource) bool {
	l := ns.Object.GetLabels()
	if l["istio-injection"] == "enabled" {
		return true
	}
	_, hasRev := l["istio.io/rev"]
	return hasRev
}

// authzPolicy is the subset of an AuthorizationPolicy this check
// evaluates: only spec.selector.matchLabels (or its absence, meaning
// namespace-wide) and spec.action. The newer targetRefs/targetRef
// (Gateway API-style) selection is deliberately not simulated — see the
// finding's own VerificationSteps.
type authzPolicy struct {
	selector map[string]string
	allows   bool // action == "ALLOW" or unset (Istio's documented default)
}

// AnalyzeAuthorizationCoverage flags workloads in an Istio-injected
// namespace with no applicable ALLOW AuthorizationPolicy
// (security-requirements.txt 6.4.2). Istio's documented default with zero
// policies selecting a workload is allow-all; only once an ALLOW policy
// exists for it does the effective default flip to deny-by-default. A
// DENY-only or AUDIT-only policy selecting the workload does NOT count as
// coverage here for exactly that reason — see the finding's own
// VerificationSteps for the nuance.
func AnalyzeAuthorizationCoverage(resources []loader.Resource, source string) ([]findings.Finding, error) {
	meshNamespaces := map[string]bool{}
	policiesByNS := map[string][]authzPolicy{}
	var workloads []loader.Resource

	for _, r := range resources {
		gvk := r.GVK()
		switch {
		case gvk.Group == "" && gvk.Kind == "Namespace":
			if meshEnabled(r) {
				meshNamespaces[r.Name()] = true
			}
		case isAuthzPolicyGVK(gvk):
			p, err := parseAuthzPolicy(r)
			if err != nil {
				return nil, fmt.Errorf("parsing AuthorizationPolicy %s/%s: %w", r.Namespace(), r.Name(), err)
			}
			policiesByNS[r.Namespace()] = append(policiesByNS[r.Namespace()], p)
		default:
			if isWorkloadGVK(gvk) {
				workloads = append(workloads, r)
			}
		}
	}

	var out []findings.Finding
	for _, w := range workloads {
		ns := w.Namespace()
		if ns == "" || !meshNamespaces[ns] {
			continue
		}
		if isCoveredByAllowPolicy(podTemplateLabels(w), policiesByNS[ns]) {
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
			Title:    "[ALPHA] Mesh workload has no ALLOW AuthorizationPolicy",
			Severity: findings.SeverityHigh,
			Category: "istio",
			Resource: ref,
			Message: fmt.Sprintf(
				"Namespace %q has Istio sidecar injection enabled, but no AuthorizationPolicy with action ALLOW "+
					"(or unset, which defaults to ALLOW) selects this workload — Istio's default with no such "+
					"policy is allow-all: any source in the mesh (or, without mTLS enforcement, outside it too) "+
					"can call this workload.",
				ns),
			Remediation: "Add an AuthorizationPolicy (workload-scoped selector, or namespace-wide with an empty " +
				"selector) with action: ALLOW and explicit from/source restrictions — this both documents " +
				"intended callers and switches Istio's default for this workload from allow-all to " +
				"deny-by-default.",
			VerificationSteps: "1. [ALPHA] Detection is deliberately narrow: only spec.selector.matchLabels (or " +
				"an empty selector, namespace-wide) is evaluated — the newer targetRefs/targetRef " +
				"(Gateway API-style) selection isn't simulated, so a workload actually covered only via " +
				"targetRefs is a false positive here. 2. A DENY-only or AUDIT-only AuthorizationPolicy selecting " +
				"this workload does NOT count as coverage for this check — Istio's allow-all default persists " +
				"until an ALLOW policy exists, so a workload with only a DENY policy is still open to everything " +
				"not explicitly denied. 3. Confirm sidecar injection is actually active for this specific " +
				"workload (a pod-level sidecar.istio.io/inject: \"false\" override can opt a workload out even " +
				"in an injection-enabled namespace) before treating this as a real gap.",
			Source: w.Source,
		})
	}
	return out, nil
}

func parseAuthzPolicy(r loader.Resource) (authzPolicy, error) {
	selector, _, err := unstructured.NestedStringMap(r.Object.Object, "spec", "selector", "matchLabels")
	if err != nil {
		return authzPolicy{}, err
	}
	action, _, err := unstructured.NestedString(r.Object.Object, "spec", "action")
	if err != nil {
		return authzPolicy{}, err
	}
	return authzPolicy{selector: selector, allows: action == "" || action == "ALLOW"}, nil
}

func isCoveredByAllowPolicy(workloadLabels map[string]string, policies []authzPolicy) bool {
	for _, p := range policies {
		if !p.allows {
			continue
		}
		if selectorMatches(p.selector, workloadLabels) {
			return true
		}
	}
	return false
}

// selectorMatches reports whether every key/value in selector is present
// in workloadLabels — Istio's WorkloadSelector only supports matchLabels
// (no matchExpressions), and an empty/nil selector matches every workload
// in the namespace.
func selectorMatches(selector, workloadLabels map[string]string) bool {
	for k, v := range selector {
		if workloadLabels[k] != v {
			return false
		}
	}
	return true
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
