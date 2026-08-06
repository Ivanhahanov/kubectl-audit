package rbac

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

// alwaysVisibleSystemSubjects are "system:"-prefixed identities that must
// NOT be dropped by filterBuiltinSystemSubjects even when
// includeSystemSubjects is false: granting them anything is itself the
// misconfiguration this analysis (and rbac.no-anonymous-binding) exists to
// catch.
var alwaysVisibleSystemSubjects = map[string]bool{
	"system:anonymous":       true,
	"system:unauthenticated": true,
}

// filterBuiltinSystemSubjects drops Group/User subjects with the reserved
// "system:" prefix before least-privilege analysis runs. system:masters,
// system:nodes, system:kube-scheduler, and friends are Kubernetes' own
// built-in bootstrap/control-plane identities, not something an operator
// can remediate by editing RBAC — system:masters in particular bypasses
// RBAC entirely at the authorization layer, and a ClusterRoleBinding to it
// is how every kubeadm/kind cluster satisfies "some identity must have full
// access to bootstrap the rest of RBAC," not a misconfiguration to fix.
//
// This mirrors loader.FilterSystemRBAC's treatment of system:-named
// Role/ClusterRole/*Binding objects, extended to subjects referenced
// *within* bindings (which aren't standalone API objects
// FilterSystemRBAC can see, so it can't already catch this). Gated by the
// same --include-system-rbac flag.
func filterBuiltinSystemSubjects(perms map[SubjectKey]*SubjectPermissions) map[SubjectKey]*SubjectPermissions {
	out := make(map[SubjectKey]*SubjectPermissions, len(perms))
	for sk, sp := range perms {
		if (sk.Kind == "Group" || sk.Kind == "User") &&
			strings.HasPrefix(sk.Name, "system:") &&
			!alwaysVisibleSystemSubjects[sk.Name] {
			continue
		}
		out[sk] = sp
	}
	return out
}

var escalationVerbs = []string{"escalate", "bind", "impersonate"}
var execResources = []string{"pods/exec", "pods/attach", "pods/portforward"}
var rbacSelfModResources = []string{"roles", "clusterroles", "rolebindings", "clusterrolebindings"}
var writeVerbs = []string{"create", "update", "patch", "delete", "deletecollection"}

// AnalyzeLeastPrivilege inspects the effective permission set of every
// subject and returns findings for violations that require cross-object
// (binding + role) analysis: privilege-escalation verbs, exec/attach
// access, broad secrets access, RBAC self-modification, and unnecessary
// ServiceAccount token automount.
func AnalyzeLeastPrivilege(g *Graph, perms map[SubjectKey]*SubjectPermissions, source string) []findings.Finding {
	var out []findings.Finding

	for _, sp := range perms {
		out = append(out, checkEscalationVerbs(sp, source)...)
		out = append(out, checkExecAccess(sp, source)...)
		out = append(out, checkSecretsBreadth(sp, source)...)
		out = append(out, checkRBACSelfModification(sp, source)...)
	}

	out = append(out, checkDefaultServiceAccountBindings(g, perms, source)...)
	out = append(out, checkAutomountWithSensitiveAccess(g, perms, source)...)
	// Runs on the Graph directly (not the possibly-filtered perms map): this
	// is the one check that's specifically *about* system:masters usage, so
	// it must see it regardless of includeSystemSubjects/filterBuiltinSystemSubjects.
	out = append(out, checkSystemMastersUsage(g, source)...)

	return out
}

// checkSystemMastersUsage reports every binding of the built-in
// system:masters group, low-severity and worded as "expected at bootstrap,
// track it" rather than "misconfiguration, fix it" — unlike the generic
// least-privilege checks this deliberately does NOT get suppressed by
// filterBuiltinSystemSubjects, since seeing every system:masters binding
// (and confirming none beyond the expected bootstrap one exist) is exactly
// the point.
func checkSystemMastersUsage(g *Graph, source string) []findings.Finding {
	const subjectName = "system:masters"
	var out []findings.Finding
	seen := map[string]bool{}

	report := func(bindingKind, bindingName, namespace string) {
		key := bindingKind + "|" + namespace + "|" + bindingName
		if seen[key] {
			return
		}
		seen[key] = true
		ref := findings.ResourceRef{Kind: "Group", Name: subjectName}
		scope := scopeLabel(namespace)
		out = append(out, finding(
			"rbac-analyzer.system-masters-usage",
			"system:masters group is bound to a role",
			findings.SeverityLow,
			[]string{"5.1.7"},
			ref,
			fmt.Sprintf("%s %q binds the built-in system:masters group %s. system:masters bypasses RBAC entirely at the authorization layer (it's not a permission grant that can be narrowed) — one binding for cluster bootstrap is expected on self-hosted clusters, but any binding beyond that should be investigated.",
				bindingKind, bindingName, scope),
			"Confirm this binding is the expected cluster-bootstrap one (commonly named \"cluster-admin\") and not an additional, avoidable grant to system:masters.",
			source,
			key,
		))
	}

	for _, rb := range g.RoleBindings {
		for _, s := range rb.Subjects {
			if s.Kind == "Group" && s.Name == subjectName {
				report("RoleBinding", rb.Name, rb.Namespace)
			}
		}
	}
	for _, crb := range g.ClusterRoleBindings {
		for _, s := range crb.Subjects {
			if s.Kind == "Group" && s.Name == subjectName {
				report("ClusterRoleBinding", crb.Name, "")
			}
		}
	}
	return out
}

func subjectRef(sk SubjectKey) findings.ResourceRef {
	return findings.ResourceRef{Kind: sk.Kind, Namespace: sk.Namespace, Name: sk.Name}
}

// subjectLabel names a subject with its namespace inline for ServiceAccounts
// — redundant with the finding's Resource field, but resilient to how a
// report renders that field, and much clearer when skimming a long flat
// finding list. Group/User subjects have no namespace to state; see
// subjectScopeNote for the clarification they need instead.
func subjectLabel(sk SubjectKey) string {
	if sk.Kind == "ServiceAccount" {
		return fmt.Sprintf("ServiceAccount %q in namespace %q", sk.Name, sk.Namespace)
	}
	return fmt.Sprintf("%s %q", sk.Kind, sk.Name)
}

// subjectScopeNote clarifies, for Group/User subjects only, that they're not
// tied to one namespace the way a ServiceAccount is — without this, "where
// do I even look for this" is a real, reported source of confusion, since a
// Group/User grant could come from a RoleBinding in any namespace or a
// ClusterRoleBinding.
func subjectScopeNote(sk SubjectKey) string {
	if sk.Kind == "ServiceAccount" {
		return ""
	}
	return fmt.Sprintf(" %s %q is a cluster-wide identity, not tied to one namespace — check every RoleBinding/ClusterRoleBinding subject list for this exact name to find where it's actually granted.", sk.Kind, sk.Name)
}

// bindingLabel names the actual Role/ClusterRoleBinding or RoleBinding
// object granting access — not just the Role/ClusterRole it points at.
// Citing only the Role/ClusterRole name is close to useless for tracking
// down what to edit/delete: the same ClusterRole is commonly bound to many
// different subjects via many different bindings, and "via ClusterRole X"
// alone doesn't say which of them involves this particular subject.
func bindingLabel(via BindingRef) string {
	if via.BindingNamespace != "" {
		return fmt.Sprintf("%s %q", via.BindingKind, via.BindingNamespace+"/"+via.BindingName)
	}
	return fmt.Sprintf("%s %q", via.BindingKind, via.BindingName)
}

func finding(policyID, title string, sev findings.Severity, cis []string, ref findings.ResourceRef, message, remediation, source string, discriminator ...string) findings.Finding {
	return findings.Finding{
		ID:          findings.NewID(policyID, ref, discriminator...),
		PolicyID:    policyID,
		Title:       title,
		Severity:    sev,
		Category:    "rbac",
		CIS:         cis,
		Resource:    ref,
		Message:     message,
		Remediation: remediation,
		Source:      source,
	}
}

func checkEscalationVerbs(sp *SubjectPermissions, source string) []findings.Finding {
	var out []findings.Finding
	seen := map[string]bool{}
	for _, r := range sp.Rules {
		for _, v := range r.Verbs {
			if !contains(escalationVerbs, v) {
				continue
			}
			key := v + "|" + r.Via.BindingKind + "|" + r.Via.BindingNamespace + "|" + r.Via.BindingName
			if seen[key] {
				continue
			}
			seen[key] = true
			ref := subjectRef(sp.Subject)
			out = append(out, finding(
				"rbac-analyzer.escalation-verb",
				"Subject has an RBAC privilege-escalation verb",
				findings.SeverityCritical,
				[]string{"5.1.3"},
				ref,
				fmt.Sprintf("%s can use the %q verb via %s → %s %q, which can be used to grant itself additional permissions.%s",
					subjectLabel(sp.Subject), v, bindingLabel(r.Via), r.Via.RoleKind, r.Via.RoleName, subjectScopeNote(sp.Subject)),
				"Remove escalate/bind/impersonate from this role unless the subject is a trusted, audited controller that genuinely needs it.",
				source,
				key,
			))
		}
	}
	return out
}

func checkExecAccess(sp *SubjectPermissions, source string) []findings.Finding {
	var out []findings.Finding
	seen := map[string]bool{}
	for _, r := range sp.Rules {
		if !containsAny(r.Resources, execResources) && !contains(r.Resources, "*") {
			continue
		}
		if !containsAny(r.Verbs, []string{"create", "get", "*"}) {
			continue
		}
		key := r.Via.BindingKind + "|" + r.Via.BindingNamespace + "|" + r.Via.BindingName
		if seen[key] {
			continue
		}
		seen[key] = true
		ref := subjectRef(sp.Subject)
		scope := scopeLabel(r.Namespace)
		out = append(out, finding(
			"rbac-analyzer.pod-exec-access",
			"Subject can exec/attach/port-forward into pods",
			findings.SeverityHigh,
			[]string{"5.1.3"},
			ref,
			fmt.Sprintf("%s can create pods/exec, pods/attach, or pods/portforward %s via %s → %s %q, which is equivalent to shell access on any matching pod.%s",
				subjectLabel(sp.Subject), scope, bindingLabel(r.Via), r.Via.RoleKind, r.Via.RoleName, subjectScopeNote(sp.Subject)),
			"Restrict pods/exec, pods/attach, and pods/portforward to a small, audited set of subjects, ideally scoped with resourceNames.",
			source,
			key,
		))
	}
	return out
}

func checkSecretsBreadth(sp *SubjectPermissions, source string) []findings.Finding {
	readVerbs := []string{"get", "list", "watch", "*"}
	clusterWide := false
	namespaces := map[string]bool{}
	seenBindings := map[string]bool{}
	var bindingLabels []string

	for _, r := range sp.Rules {
		if !containsAny(r.Resources, []string{"secrets", "*"}) {
			continue
		}
		if !containsAny(r.Verbs, readVerbs) {
			continue
		}
		if r.Namespace == "" {
			clusterWide = true
		} else {
			namespaces[r.Namespace] = true
		}
		bl := fmt.Sprintf("%s → %s %q", bindingLabel(r.Via), r.Via.RoleKind, r.Via.RoleName)
		if !seenBindings[bl] {
			seenBindings[bl] = true
			bindingLabels = append(bindingLabels, bl)
		}
	}

	if !clusterWide && len(namespaces) <= 1 {
		return nil
	}

	sort.Strings(bindingLabels)
	via := strings.Join(bindingLabels, "; ")

	ref := subjectRef(sp.Subject)
	var message string
	sev := findings.SeverityMedium
	if clusterWide {
		sev = findings.SeverityHigh
		message = fmt.Sprintf("%s can read Secrets cluster-wide, via: %s.%s", subjectLabel(sp.Subject), via, subjectScopeNote(sp.Subject))
	} else {
		message = fmt.Sprintf("%s can read Secrets across %d namespaces, via: %s.%s", subjectLabel(sp.Subject), len(namespaces), via, subjectScopeNote(sp.Subject))
	}
	return []findings.Finding{finding(
		"rbac-analyzer.broad-secrets-access",
		"Broad Secrets read access",
		sev,
		[]string{"5.1.3"},
		ref,
		message,
		"Scope secret access to a single namespace and, where possible, to specific resourceNames instead of every Secret.",
		source,
	)}
}

func checkRBACSelfModification(sp *SubjectPermissions, source string) []findings.Finding {
	seen := map[string]bool{}
	var out []findings.Finding
	for _, r := range sp.Rules {
		if !containsAny(r.Resources, rbacSelfModResources) && !contains(r.Resources, "*") {
			continue
		}
		if !containsAny(r.Verbs, writeVerbs) && !contains(r.Verbs, "*") {
			continue
		}
		key := r.Via.BindingKind + "|" + r.Via.BindingNamespace + "|" + r.Via.BindingName
		if seen[key] {
			continue
		}
		seen[key] = true
		ref := subjectRef(sp.Subject)
		out = append(out, finding(
			"rbac-analyzer.rbac-self-modification",
			"Subject can modify RBAC objects",
			findings.SeverityHigh,
			[]string{"5.1.3"},
			ref,
			fmt.Sprintf("%s can create/update/patch/delete Roles, ClusterRoles, or *Bindings %s via %s → %s %q, allowing it to grant itself further access.%s",
				subjectLabel(sp.Subject), scopeLabel(r.Namespace), bindingLabel(r.Via), r.Via.RoleKind, r.Via.RoleName, subjectScopeNote(sp.Subject)),
			"Remove write access to RBAC resources from this role unless the subject is a trusted RBAC-management controller.",
			source,
			key,
		))
	}
	return out
}

func checkDefaultServiceAccountBindings(g *Graph, perms map[SubjectKey]*SubjectPermissions, source string) []findings.Finding {
	var out []findings.Finding
	var namespaces []string
	for _, sa := range g.ServiceAccounts {
		if sa.Name == "default" {
			namespaces = append(namespaces, sa.Namespace)
		}
	}
	sort.Strings(namespaces)
	for _, ns := range namespaces {
		sk := SubjectKey{Kind: "ServiceAccount", Namespace: ns, Name: "default"}
		sp, ok := perms[sk]
		if !ok || len(sp.Rules) == 0 {
			continue
		}
		ref := subjectRef(sk)
		out = append(out, finding(
			"rbac-analyzer.default-serviceaccount-bound",
			"Default ServiceAccount has RBAC permissions bound to it",
			findings.SeverityMedium,
			[]string{"5.1.5"},
			ref,
			fmt.Sprintf("The 'default' ServiceAccount in namespace %q has one or more roles bound to it; every pod in that namespace that doesn't set a dedicated serviceAccountName inherits this access.", ns),
			"Create a dedicated ServiceAccount per workload and bind roles to it instead of the namespace's default ServiceAccount.",
			source,
		))
	}
	return out
}

func checkAutomountWithSensitiveAccess(g *Graph, perms map[SubjectKey]*SubjectPermissions, source string) []findings.Finding {
	var out []findings.Finding
	for _, sa := range g.ServiceAccounts {
		if sa.AutomountServiceAccountToken != nil && !*sa.AutomountServiceAccountToken {
			continue // explicitly disabled, nothing to flag
		}
		sk := SubjectKey{Kind: "ServiceAccount", Namespace: sa.Namespace, Name: sa.Name}
		sp, ok := perms[sk]
		if !ok || !hasSensitiveAccess(sp) {
			continue
		}
		ref := subjectRef(sk)
		out = append(out, finding(
			"rbac-analyzer.automount-with-sensitive-access",
			"ServiceAccount token automount not disabled despite sensitive RBAC access",
			findings.SeverityMedium,
			[]string{"5.1.6"},
			ref,
			fmt.Sprintf("ServiceAccount %q/%q has sensitive permissions (secrets, write access, or RBAC objects) bound to it and does not set automountServiceAccountToken: false, so every pod using it gets a token capable of exercising that access.", sa.Namespace, sa.Name),
			"Set automountServiceAccountToken: false on the ServiceAccount (or the pod spec) unless the workload genuinely needs to call the API server.",
			source,
		))
	}
	return out
}

func hasSensitiveAccess(sp *SubjectPermissions) bool {
	for _, r := range sp.Rules {
		if containsAny(r.Resources, []string{"secrets", "*"}) && containsAny(r.Verbs, []string{"get", "list", "watch", "*"}) {
			return true
		}
		if (containsAny(r.Resources, rbacSelfModResources) || contains(r.Resources, "*")) && (containsAny(r.Verbs, writeVerbs) || contains(r.Verbs, "*")) {
			return true
		}
		for _, v := range r.Verbs {
			if contains(escalationVerbs, v) {
				return true
			}
		}
	}
	return false
}

func scopeLabel(namespace string) string {
	if namespace == "" {
		return "cluster-wide"
	}
	return fmt.Sprintf("in namespace %q", namespace)
}

func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

func containsAny(list []string, items []string) bool {
	for _, item := range items {
		if contains(list, item) {
			return true
		}
	}
	return false
}
