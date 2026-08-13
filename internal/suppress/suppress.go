// Package suppress applies config.ExclusionRule waivers to a finished set
// of findings. Suppression is deliberately post-hoc (it runs after every
// analyzer has produced its findings, not by skipping resources before
// they're scanned): matching findings still get computed, then set aside
// with their reason preserved, so a suppression rule never hides a class of
// resource from every check — only the specific (policy, resource) pairs it
// names — and always leaves an audit trail in the report instead of a
// silent gap.
package suppress

import (
	"path"

	"github.com/ivanhahanov/kubectl-audit/internal/config"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// Suppressed is a finding an ExclusionRule matched, paired with the reason
// that justified it — carried through to the report instead of dropped.
type Suppressed struct {
	Finding findings.Finding
	Reason  string
}

type resourceKey struct{ Kind, Namespace, Name string }

func keyOf(ref findings.ResourceRef) resourceKey {
	return resourceKey{Kind: ref.Kind, Namespace: ref.Namespace, Name: ref.Name}
}

// LabelIndex maps a resource identity to its labels, built once from every
// loaded resource so Apply can evaluate label-based rules without each
// analyzer having to carry labels through findings.Finding itself.
type LabelIndex map[resourceKey]map[string]string

// BuildLabelIndex indexes every loaded resource's labels by (kind,
// namespace, name), so exclusion rules can match on them even though
// findings.Finding itself only carries a ResourceRef, not the source
// object.
func BuildLabelIndex(resources []loader.Resource) LabelIndex {
	idx := make(LabelIndex, len(resources))
	for _, r := range resources {
		k := resourceKey{Kind: r.GVK().Kind, Namespace: r.Namespace(), Name: r.Name()}
		idx[k] = r.Object.GetLabels()
	}
	return idx
}

// Apply splits all into findings that survive (kept) and findings matched
// by at least one exclusion rule (suppressed, paired with the reason of the
// first rule that matched). Rules are evaluated in order; a finding matches
// a rule when every field the rule's Match sets agrees, and (if PolicyIDs
// is non-empty) the finding's PolicyID is in that list.
func Apply(all []findings.Finding, rules []config.ExclusionRule, labels LabelIndex) (kept []findings.Finding, suppressed []Suppressed) {
	if len(rules) == 0 {
		return all, nil
	}
	for _, f := range all {
		if reason, ok := matchAny(f, rules, labels); ok {
			suppressed = append(suppressed, Suppressed{Finding: f, Reason: reason})
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}

func matchAny(f findings.Finding, rules []config.ExclusionRule, labels LabelIndex) (string, bool) {
	for _, rule := range rules {
		if matchesPolicy(f.PolicyID, rule.PolicyIDs) && matchesResource(f.Resource, rule.Match, labels) {
			return rule.Reason, true
		}
	}
	return "", false
}

func matchesPolicy(policyID string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, id := range allowed {
		if id == "*" || id == policyID {
			return true
		}
	}
	return false
}

func matchesResource(ref findings.ResourceRef, m config.ExclusionMatch, labels LabelIndex) bool {
	if m.Kind != "" && m.Kind != ref.Kind {
		return false
	}
	if m.Namespace != "" && m.Namespace != ref.Namespace {
		return false
	}
	if m.Name != "" {
		if ok, err := path.Match(m.Name, ref.Name); err != nil || !ok {
			return false
		}
	}
	if len(m.Labels) > 0 {
		have, ok := labels[keyOf(ref)]
		if !ok {
			return false
		}
		for k, v := range m.Labels {
			if have[k] != v {
				return false
			}
		}
	}
	return true
}
