package engine

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// MatchInput is the subset of resource identity needed to evaluate a
// policy's matchConstraints.
type MatchInput struct {
	GVK             schema.GroupVersionKind
	Namespace       string
	ObjectLabels    map[string]string
	NamespaceLabels map[string]string // nil when the namespace object wasn't loaded
}

// Matches reports whether a resource satisfies a policy's matchConstraints.
// Operations (CREATE/UPDATE/DELETE) are not filtered on: the audit engine
// evaluates standing state rather than simulating a specific admission
// request, so every resource is treated as matching regardless of the
// rule's declared operations.
func Matches(mc *admissionregistrationv1.MatchResources, in MatchInput) bool {
	if mc == nil {
		return true
	}

	resourceName, ok := loader.ResourceNameForKind(in.GVK.Kind)
	if !ok {
		return false
	}

	if len(mc.ResourceRules) > 0 {
		matched := false
		for _, rule := range mc.ResourceRules {
			if ruleMatches(rule, in.GVK.Group, in.GVK.Version, resourceName) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	for _, rule := range mc.ExcludeResourceRules {
		if ruleMatches(rule, in.GVK.Group, in.GVK.Version, resourceName) {
			return false
		}
	}

	if mc.ObjectSelector != nil && !isEmptySelector(mc.ObjectSelector) {
		sel, err := metav1.LabelSelectorAsSelector(mc.ObjectSelector)
		if err == nil && !sel.Matches(labels.Set(in.ObjectLabels)) {
			return false
		}
	}

	if mc.NamespaceSelector != nil && !isEmptySelector(mc.NamespaceSelector) && in.NamespaceLabels != nil {
		sel, err := metav1.LabelSelectorAsSelector(mc.NamespaceSelector)
		if err == nil && !sel.Matches(labels.Set(in.NamespaceLabels)) {
			return false
		}
	}

	return true
}

// resourceIndex buckets compiled policies by the exact (group, resource)
// pairs their matchConstraints.resourceRules declare, so EvaluateAll only
// has to consider policies that could possibly match a given resource
// instead of scanning every bundled policy for every single resource in
// the scan. This matters as the built-in policy count grows — most
// policies are third-party-specific and only ever apply to their own
// CRD/kind (e.g. an istio.* policy can never match a Deployment), so a
// full O(resources × policies) scan spends most of its time on
// comparisons that were always going to fail.
//
// Every bundled policy declares explicit (non-"*") apiGroups/resources —
// true of every policies/*.yaml file as of this writing. A policy with a
// wildcard apiGroup/resource, or no resourceRules at all (which Matches
// treats as matching unconditionally on that axis), falls back into
// "always" instead of a specific bucket, so correctness holds even if
// that convention is ever broken by a future policy — it just won't get
// the fast path.
type resourceIndex struct {
	byGroupResource map[string][]*CompiledPolicy
	always          []*CompiledPolicy
}

func buildResourceIndex(policies []*CompiledPolicy) *resourceIndex {
	idx := &resourceIndex{byGroupResource: make(map[string][]*CompiledPolicy)}
	for _, p := range policies {
		mc := p.Policy.Spec.MatchConstraints
		if mc == nil || len(mc.ResourceRules) == 0 {
			idx.always = append(idx.always, p)
			continue
		}
		keys := map[string]bool{}
		wildcard := false
		for _, rule := range mc.ResourceRules {
			for _, g := range rule.APIGroups {
				for _, r := range rule.Resources {
					if g == "*" || r == "*" {
						wildcard = true
						continue
					}
					keys[g+"/"+r] = true
				}
			}
		}
		if wildcard {
			idx.always = append(idx.always, p)
			continue
		}
		for key := range keys {
			idx.byGroupResource[key] = append(idx.byGroupResource[key], p)
		}
	}
	return idx
}

// candidates returns every policy that could possibly match a resource of
// the given (group, resource) — still subject to the full Matches() check
// (apiVersion, namespace/object selectors) by the caller.
func (idx *resourceIndex) candidates(group, resource string) []*CompiledPolicy {
	if len(idx.always) == 0 {
		return idx.byGroupResource[group+"/"+resource]
	}
	out := make([]*CompiledPolicy, 0, len(idx.always)+len(idx.byGroupResource[group+"/"+resource]))
	out = append(out, idx.always...)
	out = append(out, idx.byGroupResource[group+"/"+resource]...)
	return out
}

func isEmptySelector(sel *metav1.LabelSelector) bool {
	return sel == nil || (len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0)
}

func ruleMatches(rule admissionregistrationv1.NamedRuleWithOperations, group, version, resource string) bool {
	return stringMatches(rule.APIGroups, group) &&
		stringMatches(rule.APIVersions, version) &&
		stringMatches(rule.Resources, resource)
}

func stringMatches(list []string, val string) bool {
	if len(list) == 0 {
		return true
	}
	for _, item := range list {
		if item == "*" || item == val {
			return true
		}
	}
	return false
}
