package engine

// Direct, table-driven unit tests for match.go's Matches/candidates/
// buildResourceIndex/isEmptySelector/ruleMatches/stringMatches — the
// mechanism that decides whether a policy applies to a resource at all.
// Before this file, only TestEvaluateAll_IndexMatchesNaiveScan (match_test.go)
// exercised this code, and only indirectly (differential-testing the index
// against a naive scan across whatever the bundled policies + fixtures
// happen to produce) — it can't catch a bug that makes both paths agree on
// the same wrong answer, and it never calls Matches directly at all. A bug
// here is the most dangerous class for a security tool: a policy silently
// never firing on a resource it should, with no error anywhere.

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

func ruleWithOps(apiGroups, apiVersions, resources []string) admissionregistrationv1.NamedRuleWithOperations {
	return admissionregistrationv1.NamedRuleWithOperations{
		RuleWithOperations: admissionregistrationv1.RuleWithOperations{
			Operations: []admissionregistrationv1.OperationType{"*"},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   apiGroups,
				APIVersions: apiVersions,
				Resources:   resources,
			},
		},
	}
}

func podInput() MatchInput {
	return MatchInput{GVK: schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}, Namespace: "default"}
}

func TestMatches_NilMatchConstraintsAlwaysMatches(t *testing.T) {
	if !Matches(nil, podInput()) {
		t.Error("expected a nil MatchResources to match unconditionally")
	}
}

func TestMatches_UnknownKindNeverMatches(t *testing.T) {
	in := MatchInput{GVK: schema.GroupVersionKind{Group: "totally.unknown", Version: "v1", Kind: "NotARegisteredKind"}}
	mc := &admissionregistrationv1.MatchResources{
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{ruleWithOps([]string{"*"}, []string{"*"}, []string{"*"})},
	}
	if Matches(mc, in) {
		t.Error("expected a Kind absent from loader.ResourceNameForKind to never match, even against a wildcard rule")
	}
}

func TestMatches_ResourceRulesIncludeExclude(t *testing.T) {
	mc := &admissionregistrationv1.MatchResources{
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
			ruleWithOps([]string{""}, []string{"v1"}, []string{"pods"}),
		},
	}
	if !Matches(mc, podInput()) {
		t.Error("expected a resource listed in resourceRules to match")
	}

	notListed := MatchInput{GVK: schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"}}
	if Matches(mc, notListed) {
		t.Error("expected a resource absent from a non-empty resourceRules to not match")
	}

	excluded := &admissionregistrationv1.MatchResources{
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
			ruleWithOps([]string{""}, []string{"v1"}, []string{"pods"}),
		},
		ExcludeResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
			ruleWithOps([]string{""}, []string{"v1"}, []string{"pods"}),
		},
	}
	if Matches(excluded, podInput()) {
		t.Error("expected excludeResourceRules to take precedence over a matching resourceRules entry")
	}
}

func TestMatches_ObjectSelectorFiltersOnLabels(t *testing.T) {
	mc := &admissionregistrationv1.MatchResources{
		ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
	}
	in := podInput()
	in.ObjectLabels = map[string]string{"env": "prod"}
	if !Matches(mc, in) {
		t.Error("expected an object whose labels satisfy the selector to match")
	}
	in.ObjectLabels = map[string]string{"env": "staging"}
	if Matches(mc, in) {
		t.Error("expected an object whose labels don't satisfy the selector to not match")
	}

	empty := &admissionregistrationv1.MatchResources{ObjectSelector: &metav1.LabelSelector{}}
	if !Matches(empty, podInput()) {
		t.Error("expected an empty (non-nil) ObjectSelector to match everything, per isEmptySelector")
	}
}

func TestMatches_NamespaceSelectorFiltersOnNamespaceLabels(t *testing.T) {
	mc := &admissionregistrationv1.MatchResources{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "platform"}},
	}
	in := podInput()
	in.NamespaceLabels = map[string]string{"team": "platform"}
	if !Matches(mc, in) {
		t.Error("expected a namespace whose labels satisfy the selector to match")
	}
	in.NamespaceLabels = map[string]string{"team": "other"}
	if Matches(mc, in) {
		t.Error("expected a namespace whose labels don't satisfy the selector to not match")
	}

	// Documented edge case (match.go): NamespaceLabels == nil means the
	// namespace object wasn't loaded at all — must match unconditionally,
	// not be treated as "labels {}" and filtered out. A real, easy-to-break
	// invariant that had no test before this file.
	in.NamespaceLabels = nil
	if !Matches(mc, in) {
		t.Error("expected nil NamespaceLabels (namespace object not loaded) to match unconditionally, not be filtered")
	}
}

func TestMatches_WildcardGroupOrResourceInRule(t *testing.T) {
	mc := &admissionregistrationv1.MatchResources{
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
			ruleWithOps([]string{"*"}, []string{"*"}, []string{"*"}),
		},
	}
	if !Matches(mc, podInput()) {
		t.Error("expected a fully wildcarded resourceRule to match any known-Kind resource")
	}
	other := MatchInput{GVK: schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}}
	if !Matches(mc, other) {
		t.Error("expected a fully wildcarded resourceRule to match a resource in a different group too")
	}
}

func TestIsEmptySelector(t *testing.T) {
	cases := []struct {
		name string
		sel  *metav1.LabelSelector
		want bool
	}{
		{"nil", nil, true},
		{"empty struct", &metav1.LabelSelector{}, true},
		{"matchLabels set", &metav1.LabelSelector{MatchLabels: map[string]string{"k": "v"}}, false},
		{"matchExpressions set", &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "k"}}}, false},
	}
	for _, c := range cases {
		if got := isEmptySelector(c.sel); got != c.want {
			t.Errorf("%s: isEmptySelector = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRuleMatches(t *testing.T) {
	rule := ruleWithOps([]string{"apps", "batch"}, []string{"v1"}, []string{"deployments", "jobs"})
	if !ruleMatches(rule, "apps", "v1", "deployments") {
		t.Error("expected an exact (group, version, resource) match")
	}
	if ruleMatches(rule, "networking.k8s.io", "v1", "ingresses") {
		t.Error("expected a group not listed in the rule to not match")
	}
	wildcard := ruleWithOps([]string{"*"}, []string{"*"}, []string{"*"})
	if !ruleMatches(wildcard, "anything", "v1beta1", "whatever") {
		t.Error("expected a wildcarded rule to match any (group, version, resource)")
	}
}

func TestStringMatches(t *testing.T) {
	if !stringMatches(nil, "anything") {
		t.Error("expected an empty/nil list to match anything (the 'no constraint' convention)")
	}
	if !stringMatches([]string{"*"}, "anything") {
		t.Error("expected a literal \"*\" entry to match anything")
	}
	if !stringMatches([]string{"a", "b"}, "b") {
		t.Error("expected a listed value to match")
	}
	if stringMatches([]string{"a", "b"}, "c") {
		t.Error("expected an unlisted value in a non-empty list to not match")
	}
}

func TestBuildResourceIndex_WildcardPolicyGoesToAlways(t *testing.T) {
	wildcardGroup := &CompiledPolicy{
		Meta: PolicyMeta{ID: "wildcard-group"},
		Policy: &admissionregistrationv1.ValidatingAdmissionPolicy{Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{ruleWithOps([]string{"*"}, []string{"v1"}, []string{"pods"})},
			},
		}},
	}
	wildcardResource := &CompiledPolicy{
		Meta: PolicyMeta{ID: "wildcard-resource"},
		Policy: &admissionregistrationv1.ValidatingAdmissionPolicy{Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{ruleWithOps([]string{"apps"}, []string{"v1"}, []string{"*"})},
			},
		}},
	}
	specific := &CompiledPolicy{
		Meta: PolicyMeta{ID: "specific"},
		Policy: &admissionregistrationv1.ValidatingAdmissionPolicy{Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{ruleWithOps([]string{"apps"}, []string{"v1"}, []string{"deployments"})},
			},
		}},
	}

	idx := buildResourceIndex([]*CompiledPolicy{wildcardGroup, wildcardResource, specific})

	always := map[string]bool{}
	for _, p := range idx.always {
		always[p.Meta.ID] = true
	}
	if !always["wildcard-group"] {
		t.Error("expected a wildcarded apiGroup to land in the always bucket")
	}
	if !always["wildcard-resource"] {
		t.Error("expected a wildcarded resource to land in the always bucket")
	}
	if always["specific"] {
		t.Error("expected a fully-specific policy to NOT land in the always bucket")
	}
	found := false
	for _, p := range idx.byGroupResource["apps/deployments"] {
		if p.Meta.ID == "specific" {
			found = true
		}
	}
	if !found {
		t.Error("expected the specific policy to be bucketed under apps/deployments")
	}
}

func TestBuildResourceIndex_NoResourceRulesGoesToAlways(t *testing.T) {
	noRules := &CompiledPolicy{
		Meta: PolicyMeta{ID: "no-rules"},
		Policy: &admissionregistrationv1.ValidatingAdmissionPolicy{Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			MatchConstraints: &admissionregistrationv1.MatchResources{},
		}},
	}
	nilConstraints := &CompiledPolicy{
		Meta:   PolicyMeta{ID: "nil-constraints"},
		Policy: &admissionregistrationv1.ValidatingAdmissionPolicy{Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{}},
	}

	idx := buildResourceIndex([]*CompiledPolicy{noRules, nilConstraints})
	if len(idx.always) != 2 {
		t.Fatalf("expected both policies (empty resourceRules and nil MatchConstraints) in the always bucket, got %d", len(idx.always))
	}
}

func TestResourceIndex_Candidates_CombinesAlwaysAndSpecific(t *testing.T) {
	always := &CompiledPolicy{Meta: PolicyMeta{ID: "always"}}
	specific := &CompiledPolicy{Meta: PolicyMeta{ID: "specific"}}
	idx := &resourceIndex{
		byGroupResource: map[string][]*CompiledPolicy{"apps/deployments": {specific}},
		always:          []*CompiledPolicy{always},
	}

	got := idx.candidates("apps", "deployments")
	if len(got) != 2 {
		t.Fatalf("expected both the always-bucket and the specific-bucket policy, got %d", len(got))
	}

	// A (group, resource) with no specific bucket must still return the
	// always-bucket policies, not an empty slice.
	got = idx.candidates("networking.k8s.io", "ingresses")
	if len(got) != 1 || got[0].Meta.ID != "always" {
		t.Errorf("expected only the always-bucket policy for an unrelated resource, got %v", got)
	}
}

// TestBundledPolicies_ResourceRulesNameOnlyKnownResources guards against the
// silent-false-negative class the audit flagged directly: a bundled
// policy's matchConstraints.resourceRules naming a resource no loaded
// object's Kind could ever resolve to (a typo in apiGroups/resources, or a
// Kind never added to loader.kindToResource) means that policy can never
// match anything, on any cluster — with no error anywhere, since Matches
// simply returns false for every resource forever.
func TestBundledPolicies_ResourceRulesNameOnlyKnownResources(t *testing.T) {
	policies, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	for _, p := range policies {
		mc := p.Policy.Spec.MatchConstraints
		if mc == nil {
			continue
		}
		for _, rule := range mc.ResourceRules {
			for _, r := range rule.Resources {
				if r == "*" {
					continue
				}
				if !loader.IsKnownResource(r) {
					t.Errorf("policy %q declares resourceRules resource %q, which no registered Kind resolves to (loader.kindToResource) — this policy can never match any loaded object", p.Meta.ID, r)
				}
			}
		}
	}
}
