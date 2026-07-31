// Package rbac builds an effective permission model from Role/ClusterRole/
// RoleBinding/ClusterRoleBinding objects and flags least-privilege
// violations that require cross-object analysis (dangerous verb
// combinations, permission breadth across namespaces, RBAC
// self-modification) — the things a single-object VAP CEL expression can't
// see. Single-object RBAC checks (wildcard rules, cluster-admin/anonymous
// bindings) live in the bundled VAP policies instead (policies/rbac/*.yaml)
// so they can also be enforced in-cluster.
package rbac

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// Graph holds every RBAC object loaded for a scan, indexed for lookup.
type Graph struct {
	Roles               map[string]*rbacv1.Role // key: namespace/name
	ClusterRoles        map[string]*rbacv1.ClusterRole
	RoleBindings        []*rbacv1.RoleBinding
	ClusterRoleBindings []*rbacv1.ClusterRoleBinding
	ServiceAccounts     map[string]*corev1.ServiceAccount // key: namespace/name
}

const rbacGroup = "rbac.authorization.k8s.io"

// BuildGraph extracts RBAC and ServiceAccount objects out of a resource set.
func BuildGraph(resources []loader.Resource) (*Graph, error) {
	g := &Graph{
		Roles:           map[string]*rbacv1.Role{},
		ClusterRoles:    map[string]*rbacv1.ClusterRole{},
		ServiceAccounts: map[string]*corev1.ServiceAccount{},
	}
	for _, r := range resources {
		gvk := r.GVK()
		switch {
		case gvk.Group == rbacGroup && gvk.Kind == "Role":
			var role rbacv1.Role
			if err := convert(r, &role); err != nil {
				return nil, err
			}
			g.Roles[nsKey(role.Namespace, role.Name)] = &role
		case gvk.Group == rbacGroup && gvk.Kind == "ClusterRole":
			var cr rbacv1.ClusterRole
			if err := convert(r, &cr); err != nil {
				return nil, err
			}
			g.ClusterRoles[cr.Name] = &cr
		case gvk.Group == rbacGroup && gvk.Kind == "RoleBinding":
			var rb rbacv1.RoleBinding
			if err := convert(r, &rb); err != nil {
				return nil, err
			}
			g.RoleBindings = append(g.RoleBindings, &rb)
		case gvk.Group == rbacGroup && gvk.Kind == "ClusterRoleBinding":
			var crb rbacv1.ClusterRoleBinding
			if err := convert(r, &crb); err != nil {
				return nil, err
			}
			g.ClusterRoleBindings = append(g.ClusterRoleBindings, &crb)
		case gvk.Group == "" && gvk.Kind == "ServiceAccount":
			var sa corev1.ServiceAccount
			if err := convert(r, &sa); err != nil {
				return nil, err
			}
			g.ServiceAccounts[nsKey(sa.Namespace, sa.Name)] = &sa
		}
	}
	injectWellKnownClusterRoles(g)
	resolveAggregatedClusterRoles(g)
	return g, nil
}

// injectWellKnownClusterRoles adds the built-in cluster-admin ClusterRole if
// it wasn't loaded. Every real cluster auto-creates it, but static-manifest
// scans (and live scans that exclude ClusterRoles) never see its
// definition; without it, a binding to "cluster-admin" would resolve to
// zero effective permissions and the least-privilege checks that depend on
// resolved rules (e.g. default-ServiceAccount-bound) would silently miss
// the single most dangerous binding a cluster can have.
func injectWellKnownClusterRoles(g *Graph) {
	if _, ok := g.ClusterRoles["cluster-admin"]; ok {
		return
	}
	g.ClusterRoles["cluster-admin"] = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
			{NonResourceURLs: []string{"*"}, Verbs: []string{"*"}},
		},
	}
}

// resolveAggregatedClusterRoles materializes .Rules for ClusterRoles that
// use spec.aggregationRule instead of listing rules directly (e.g. the
// built-in admin/edit/view roles, or any custom role that aggregates from
// CRD-contributed ClusterRoles via a label selector).
//
// In a live cluster this is already done for us — the API server's
// ClusterRoleAggregation controller writes the resolved rules back onto
// .rules, so a loaded ClusterRole never has an empty .Rules alongside a set
// AggregationRule. Static manifests, however, are the raw source YAML: the
// aggregation is a runtime computation that never ran, so .Rules is empty
// and the role's real permissions would otherwise be silently invisible to
// the least-privilege analysis. Only ClusterRoles with empty .Rules are
// touched, so live-cluster data (already correct) is never overwritten.
//
// Aggregation can chain (a role can aggregate from another aggregated
// role), so this iterates to a fixed point with a small bound to guard
// against pathological/cyclic selectors.
func resolveAggregatedClusterRoles(g *Graph) {
	for i := 0; i < 5; i++ {
		changed := false
		for _, cr := range g.ClusterRoles {
			if cr.AggregationRule == nil || len(cr.AggregationRule.ClusterRoleSelectors) == 0 {
				continue
			}
			if len(cr.Rules) > 0 {
				continue
			}

			seen := map[string]bool{}
			var union []rbacv1.PolicyRule
			for _, sel := range cr.AggregationRule.ClusterRoleSelectors {
				selector, err := metav1.LabelSelectorAsSelector(&sel)
				if err != nil {
					continue
				}
				for otherName, other := range g.ClusterRoles {
					if otherName == cr.Name || len(other.Rules) == 0 {
						continue
					}
					if !selector.Matches(labels.Set(other.Labels)) {
						continue
					}
					for _, rule := range other.Rules {
						key := ruleKey(rule)
						if seen[key] {
							continue
						}
						seen[key] = true
						union = append(union, rule)
					}
				}
			}
			if len(union) > 0 {
				cr.Rules = union
				changed = true
			}
		}
		if !changed {
			break
		}
	}
}

func ruleKey(r rbacv1.PolicyRule) string {
	return strings.Join(r.APIGroups, ",") + "|" + strings.Join(r.Resources, ",") + "|" +
		strings.Join(r.ResourceNames, ",") + "|" + strings.Join(r.Verbs, ",") + "|" +
		strings.Join(r.NonResourceURLs, ",")
}

func convert(r loader.Resource, out interface{}) error {
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(r.Object.Object, out); err != nil {
		return fmt.Errorf("converting %s: %w", r.Object.GetName(), err)
	}
	return nil
}

func nsKey(ns, name string) string { return ns + "/" + name }
