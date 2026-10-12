// Package kyverno converts this tool's ValidatingAdmissionPolicy/CEL
// policies into Kyverno policy YAML, for organizations already
// standardized on Kyverno for in-cluster enforcement.
//
// Kyverno has two policy shapes, with one real representational gap
// between them:
//
//   - ValidatingPolicy (policies.kyverno.io/v1) reuses the exact same
//     matchConstraints (resource-matching is GVR-based: apiGroup + resource
//     plural, e.g. "deployments") and validations (CEL expression/message)
//     shapes as a native VAP — see ToValidatingPolicy. This conversion is a
//     lossless structural copy. (v1alpha1 existed briefly but is already
//     deprecated as of Kyverno's current release — confirmed live against
//     a real cluster, see the kind-cluster verification this package's
//     tests and the CLI's export command were checked against.)
//   - The classic ClusterPolicy (kyverno.io/v1) matches by Kind
//     (match.any[].resources.kinds, e.g. "Deployment") instead of GVR. A
//     VAP never carries Kind at all — Kubernetes itself only resolves
//     GVR->GVK via a live RESTMapper backed by cluster discovery, because
//     there is no reliable static algorithm for it (resource-plural ->
//     Kind is not recoverable by de-pluralizing + capitalizing for
//     multi-word Kinds, e.g. "virtualmachineinstances" ->
//     "VirtualMachineInstance" loses the internal word boundaries). See
//     KindResolver, StaticKindResolver and ToClusterPolicy.
package kyverno

import (
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/ivanhahanov/kubectl-audit/internal/engine"
)

// KindResolver resolves a GroupVersionResource (as a VAP's matchConstraints
// carries it) to the Kind string a classic Kyverno ClusterPolicy's
// match.any[].resources.kinds needs. ok is false when the resolver has no
// answer — never guess.
type KindResolver func(gvr schema.GroupVersionResource) (kind string, ok bool)

// staticKinds covers exactly the resources the bundled (non-thirdparty)
// policies use: core/v1, apps/v1, batch/v1,
// rbac.authorization.k8s.io/v1, networking.k8s.io/v1, and
// admissionregistration.k8s.io/v1. Keyed by "group/resource" ("" for the
// core group, e.g. "/pods"). Custom or thirdparty-CRD policies need a live
// cluster (see RESTMapperKindResolver) — there is no static table that
// could cover arbitrary CRDs correctly.
var staticKinds = map[string]string{
	"/pods":                                  "Pod",
	"/configmaps":                            "ConfigMap",
	"/secrets":                               "Secret",
	"/serviceaccounts":                       "ServiceAccount",
	"/namespaces":                            "Namespace",
	"/services":                              "Service",
	"apps/deployments":                       "Deployment",
	"apps/statefulsets":                      "StatefulSet",
	"apps/daemonsets":                        "DaemonSet",
	"apps/replicasets":                       "ReplicaSet",
	"batch/jobs":                             "Job",
	"batch/cronjobs":                         "CronJob",
	"rbac.authorization.k8s.io/roles":        "Role",
	"rbac.authorization.k8s.io/clusterroles": "ClusterRole",
	"rbac.authorization.k8s.io/rolebindings": "RoleBinding",
	"rbac.authorization.k8s.io/clusterrolebindings":                "ClusterRoleBinding",
	"networking.k8s.io/networkpolicies":                            "NetworkPolicy",
	"networking.k8s.io/ingresses":                                  "Ingress",
	"admissionregistration.k8s.io/mutatingwebhookconfigurations":   "MutatingWebhookConfiguration",
	"admissionregistration.k8s.io/validatingwebhookconfigurations": "ValidatingWebhookConfiguration",
}

// StaticKindResolver resolves via the built-in table above — no cluster
// needed, but only covers the bundled (non-thirdparty) policy set.
func StaticKindResolver(gvr schema.GroupVersionResource) (string, bool) {
	kind, ok := staticKinds[gvr.Group+"/"+gvr.Resource]
	return kind, ok
}

// restMapper is the one method of *restmapper.DeferredDiscoveryRESTMapper
// (internal/k8sclient.Client.RESTMapper) this package needs — narrowed to
// keep this package independent of client-go's discovery machinery in its
// own API, and trivially fakeable in tests.
type restMapper interface {
	KindFor(resource schema.GroupVersionResource) (schema.GroupVersionKind, error)
}

// RESTMapperKindResolver resolves via live cluster discovery — the general
// case, correct for any resource (including custom/thirdparty CRDs)
// actually installed on the target cluster.
func RESTMapperKindResolver(m restMapper) KindResolver {
	return func(gvr schema.GroupVersionResource) (string, bool) {
		gvk, err := m.KindFor(gvr)
		if err != nil {
			return "", false
		}
		return gvk.Kind, true
	}
}

// ChainKindResolvers tries each resolver in order, returning the first
// resolved Kind. Use StaticKindResolver first (free, no network) and
// RESTMapperKindResolver second (handles anything the static table
// doesn't, when a cluster is available).
func ChainKindResolvers(resolvers ...KindResolver) KindResolver {
	return func(gvr schema.GroupVersionResource) (string, bool) {
		for _, r := range resolvers {
			if r == nil {
				continue
			}
			if kind, ok := r(gvr); ok {
				return kind, true
			}
		}
		return "", false
	}
}

// ToValidatingPolicy converts cp into a Kyverno ValidatingPolicy document
// (as a plain map, ready for sigs.k8s.io/yaml.Marshal). matchConstraints
// and validations are copied directly from the typed VAP struct — both
// marshal through the exact same JSON field names Kyverno's ValidatingPolicy
// expects, since it reuses the native K8s admissionregistration CEL shapes
// — so there is nothing to lose or get subtly wrong here.
func ToValidatingPolicy(cp *engine.CompiledPolicy) map[string]any {
	policy := cp.Policy
	spec := map[string]any{
		"validationActions": []string{"Audit"},
		"matchConstraints":  policy.Spec.MatchConstraints,
		"validations":       policy.Spec.Validations,
	}
	if policy.Spec.FailurePolicy != nil {
		spec["failurePolicy"] = *policy.Spec.FailurePolicy
	}
	return map[string]any{
		"apiVersion": "policies.kyverno.io/v1",
		"kind":       "ValidatingPolicy",
		"metadata": map[string]any{
			"name":        policy.Name,
			"annotations": policy.Annotations,
		},
		"spec": spec,
	}
}

// ToClusterPolicy converts cp into a classic Kyverno ClusterPolicy
// document (as a plain map, ready for sigs.k8s.io/yaml.Marshal), using
// resolve to turn every matchConstraints resourceRule's GVRs into the
// Kinds a ClusterPolicy match block needs. Returns the resources (as
// "group/resource" strings) that resolve could not answer for — the
// caller should treat any non-empty result as "skip writing this file,
// warn naming these", not write a partially-correct ClusterPolicy.
func ToClusterPolicy(cp *engine.CompiledPolicy, resolve KindResolver) (doc map[string]any, unresolved []string) {
	policy := cp.Policy
	missing := map[string]bool{}
	var anyMatches []map[string]any

	for _, rule := range policy.Spec.MatchConstraints.ResourceRules {
		groups := rule.APIGroups
		if len(groups) == 0 {
			groups = []string{""}
		}
		version := ""
		if len(rule.APIVersions) > 0 {
			version = rule.APIVersions[0]
		}

		kindSet := map[string]bool{}
		for _, group := range groups {
			for _, resource := range rule.Resources {
				base := resource
				if idx := strings.Index(resource, "/"); idx >= 0 {
					base = resource[:idx] // strip subresource suffix, e.g. "pods/status" -> "pods"
				}
				key := group + "/" + base
				if base == "*" || group == "*" {
					missing[key] = true
					continue
				}
				kind, ok := resolve(schema.GroupVersionResource{Group: group, Version: version, Resource: base})
				if !ok {
					missing[key] = true
					continue
				}
				kindSet[kind] = true
			}
		}
		if len(kindSet) == 0 {
			continue
		}
		kinds := make([]string, 0, len(kindSet))
		for k := range kindSet {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		anyMatches = append(anyMatches, map[string]any{
			"resources": map[string]any{"kinds": kinds},
		})
	}

	if len(missing) > 0 {
		unresolved = make([]string, 0, len(missing))
		for k := range missing {
			unresolved = append(unresolved, k)
		}
		sort.Strings(unresolved)
		return nil, unresolved
	}

	var celExprs []map[string]any
	for _, v := range policy.Spec.Validations {
		expr := map[string]any{"expression": v.Expression}
		if v.Message != "" {
			expr["message"] = v.Message
		}
		celExprs = append(celExprs, expr)
	}

	doc = map[string]any{
		"apiVersion": "kyverno.io/v1",
		"kind":       "ClusterPolicy",
		"metadata": map[string]any{
			"name":        policy.Name,
			"annotations": policy.Annotations,
		},
		"spec": map[string]any{
			"validationFailureAction": "Audit",
			"background":              true,
			"rules": []map[string]any{
				{
					"name":  policy.Name,
					"match": map[string]any{"any": anyMatches},
					"validate": map[string]any{
						"cel": map[string]any{"expressions": celExprs},
					},
				},
			},
		},
	}
	return doc, nil
}

// UnresolvedKindError formats ToClusterPolicy's unresolved list into the
// warning callers (internal/cli's `policy export --format kyverno` command)
// print to stderr.
func UnresolvedKindError(policyID string, unresolved []string) error {
	return fmt.Errorf("policy %q: could not resolve Kind for %s (needs a live cluster — see --context/--kubeconfig)", policyID, strings.Join(unresolved, ", "))
}
