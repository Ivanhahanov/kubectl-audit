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
