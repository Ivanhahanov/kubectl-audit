package rbac

import (
	"fmt"
	"sort"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

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

	return out
}

func subjectRef(sk SubjectKey) findings.ResourceRef {
	return findings.ResourceRef{Kind: sk.Kind, Namespace: sk.Namespace, Name: sk.Name}
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
			key := v + "|" + r.Via.RoleName
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
				fmt.Sprintf("%s %q can use the %q verb (via %s %q), which can be used to grant itself additional permissions.",
					sp.Subject.Kind, sp.Subject.Name, v, r.Via.RoleKind, r.Via.RoleName),
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
		key := r.Via.RoleName + "|" + r.Namespace
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
			fmt.Sprintf("%s %q can create pods/exec, pods/attach, or pods/portforward %s (via %s %q), which is equivalent to shell access on any matching pod.",
				sp.Subject.Kind, sp.Subject.Name, scope, r.Via.RoleKind, r.Via.RoleName),
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
	}

	if !clusterWide && len(namespaces) <= 1 {
		return nil
	}

	ref := subjectRef(sp.Subject)
	var message string
	sev := findings.SeverityMedium
	if clusterWide {
		sev = findings.SeverityHigh
		message = fmt.Sprintf("%s %q can read Secrets cluster-wide.", sp.Subject.Kind, sp.Subject.Name)
	} else {
		message = fmt.Sprintf("%s %q can read Secrets across %d namespaces.", sp.Subject.Kind, sp.Subject.Name, len(namespaces))
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
		key := r.Via.RoleName + "|" + r.Namespace
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
			fmt.Sprintf("%s %q can create/update/patch/delete Roles, ClusterRoles, or *Bindings %s (via %s %q), allowing it to grant itself further access.",
				sp.Subject.Kind, sp.Subject.Name, scopeLabel(r.Namespace), r.Via.RoleKind, r.Via.RoleName),
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
