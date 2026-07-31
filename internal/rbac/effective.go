package rbac

import (
	rbacv1 "k8s.io/api/rbac/v1"
)

// SubjectKey identifies an RBAC subject.
type SubjectKey struct {
	Kind      string // User | Group | ServiceAccount
	Namespace string // only meaningful for ServiceAccount
	Name      string
}

// BindingRef records which binding+role granted a subject access, for
// provenance in the role-model report.
type BindingRef struct {
	BindingKind      string // RoleBinding | ClusterRoleBinding
	BindingNamespace string
	BindingName      string
	RoleKind         string // Role | ClusterRole
	RoleName         string
}

// EffectiveRule is one PolicyRule granted to a subject, with the namespace
// it applies in ("" means cluster-wide) and provenance.
type EffectiveRule struct {
	APIGroups []string
	Resources []string
	Verbs     []string
	Namespace string
	Via       BindingRef
}

// SubjectPermissions is the flattened, cross-object view of everything a
// subject can do.
type SubjectPermissions struct {
	Subject  SubjectKey
	Bindings []BindingRef
	Rules    []EffectiveRule
}

// ComputeEffectivePermissions walks every binding in the graph and resolves
// it against its referenced Role/ClusterRole, producing one
// SubjectPermissions per subject.
func ComputeEffectivePermissions(g *Graph) map[SubjectKey]*SubjectPermissions {
	result := map[SubjectKey]*SubjectPermissions{}

	get := func(sk SubjectKey) *SubjectPermissions {
		sp, ok := result[sk]
		if !ok {
			sp = &SubjectPermissions{Subject: sk}
			result[sk] = sp
		}
		return sp
	}

	for _, rb := range g.RoleBindings {
		var rules []rbacv1.PolicyRule
		switch rb.RoleRef.Kind {
		case "Role":
			if role, ok := g.Roles[nsKey(rb.Namespace, rb.RoleRef.Name)]; ok {
				rules = role.Rules
			}
		case "ClusterRole":
			if cr, ok := g.ClusterRoles[rb.RoleRef.Name]; ok {
				rules = cr.Rules
			}
		}
		via := BindingRef{
			BindingKind: "RoleBinding", BindingNamespace: rb.Namespace, BindingName: rb.Name,
			RoleKind: rb.RoleRef.Kind, RoleName: rb.RoleRef.Name,
		}
		for _, subj := range rb.Subjects {
			sk := subjectKeyFrom(subj, rb.Namespace)
			sp := get(sk)
			sp.Bindings = append(sp.Bindings, via)
			for _, rule := range rules {
				sp.Rules = append(sp.Rules, EffectiveRule{
					APIGroups: rule.APIGroups, Resources: rule.Resources, Verbs: rule.Verbs,
					Namespace: rb.Namespace, Via: via,
				})
			}
		}
	}

	for _, crb := range g.ClusterRoleBindings {
		var rules []rbacv1.PolicyRule
		if cr, ok := g.ClusterRoles[crb.RoleRef.Name]; ok {
			rules = cr.Rules
		}
		via := BindingRef{
			BindingKind: "ClusterRoleBinding", BindingName: crb.Name,
			RoleKind: "ClusterRole", RoleName: crb.RoleRef.Name,
		}
		for _, subj := range crb.Subjects {
			sk := subjectKeyFrom(subj, "")
			sp := get(sk)
			sp.Bindings = append(sp.Bindings, via)
			for _, rule := range rules {
				sp.Rules = append(sp.Rules, EffectiveRule{
					APIGroups: rule.APIGroups, Resources: rule.Resources, Verbs: rule.Verbs,
					Namespace: "", Via: via,
				})
			}
		}
	}

	return result
}

func subjectKeyFrom(s rbacv1.Subject, bindingNamespace string) SubjectKey {
	ns := s.Namespace
	if s.Kind == "ServiceAccount" && ns == "" {
		ns = bindingNamespace
	}
	return SubjectKey{Kind: s.Kind, Namespace: ns, Name: s.Name}
}
