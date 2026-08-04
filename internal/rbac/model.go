package rbac

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// SubjectModel is the role-model report's per-subject row: who, what
// they're bound to, a condensed permission summary, and any risk flags
// raised for them.
type SubjectModel struct {
	Subject     SubjectKey   `json:"subject"`
	Bindings    []BindingRef `json:"bindings"`
	Permissions []string     `json:"permissions"`
	RiskFlags   []string     `json:"riskFlags,omitempty"`
}

// Result bundles everything the RBAC analyzer produces from one resource set.
type Result struct {
	Findings []findings.Finding
	Model    []SubjectModel
}

// Analyze builds the RBAC graph, computes effective permissions, runs the
// least-privilege checks, and renders the role model — the single entry
// point used by both `rbac analyze` and `scan`.
//
// includeSystemSubjects mirrors --include-system-rbac: when false (the
// default), built-in Kubernetes identities like system:masters/system:nodes
// are excluded from the role model and least-privilege findings (see
// filterBuiltinSystemSubjects) since they're not remediable RBAC
// misconfigurations, just how every cluster bootstraps.
func Analyze(resources []loader.Resource, source string, includeSystemSubjects bool) (*Result, error) {
	g, err := BuildGraph(resources)
	if err != nil {
		return nil, err
	}
	perms := ComputeEffectivePermissions(g)
	if !includeSystemSubjects {
		perms = filterBuiltinSystemSubjects(perms)
	}
	findingsList := AnalyzeLeastPrivilege(g, perms, source)

	riskFlags := map[SubjectKey][]string{}
	for _, f := range findingsList {
		sk := SubjectKey{Kind: f.Resource.Kind, Namespace: f.Resource.Namespace, Name: f.Resource.Name}
		riskFlags[sk] = append(riskFlags[sk], f.Title)
	}

	var subjects []SubjectKey
	for sk := range perms {
		subjects = append(subjects, sk)
	}
	sort.Slice(subjects, func(i, j int) bool {
		if subjects[i].Kind != subjects[j].Kind {
			return subjects[i].Kind < subjects[j].Kind
		}
		if subjects[i].Namespace != subjects[j].Namespace {
			return subjects[i].Namespace < subjects[j].Namespace
		}
		return subjects[i].Name < subjects[j].Name
	})

	model := make([]SubjectModel, 0, len(subjects))
	for _, sk := range subjects {
		sp := perms[sk]
		model = append(model, SubjectModel{
			Subject:     sk,
			Bindings:    sp.Bindings,
			Permissions: summarizeRules(sp.Rules),
			RiskFlags:   riskFlags[sk],
		})
	}

	return &Result{Findings: findingsList, Model: model}, nil
}

func summarizeRules(rules []EffectiveRule) []string {
	type key struct{ scope, groups, resources string }
	bucket := map[key]map[string]bool{}
	var order []key
	for _, r := range rules {
		k := key{
			scope:     scopeLabel(r.Namespace),
			groups:    joinOrStar(r.APIGroups),
			resources: joinOrStar(r.Resources),
		}
		if bucket[k] == nil {
			bucket[k] = map[string]bool{}
			order = append(order, k)
		}
		for _, v := range r.Verbs {
			bucket[k][v] = true
		}
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		verbs := make([]string, 0, len(bucket[k]))
		for v := range bucket[k] {
			verbs = append(verbs, v)
		}
		sort.Strings(verbs)
		out = append(out, fmt.Sprintf("%s: %s %s (apiGroups: %s)", k.scope, strings.Join(verbs, ","), k.resources, k.groups))
	}
	sort.Strings(out)
	return out
}

func joinOrStar(list []string) string {
	if len(list) == 0 {
		return "(none)"
	}
	return strings.Join(list, ",")
}
