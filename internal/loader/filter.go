package loader

import "strings"

// DefaultExcludedNamespaces are platform-managed namespaces present on
// virtually every cluster (kube-system, kube-public, kube-node-lease).
// Their workloads and RBAC objects are Kubernetes/CNI/CSI internals: the
// checks that fire against them are usually structurally required (e.g.
// kube-proxy needs hostNetwork) rather than actionable misconfigurations,
// and they tend to drown out real findings from user namespaces. Excluded
// by default; pass --exclude-namespace "" or an explicit -n allowlist to
// see them anyway.
var DefaultExcludedNamespaces = []string{"kube-system", "kube-public", "kube-node-lease"}

// FilterExcludedNamespaces drops resources in the given namespaces. A
// cluster-scoped Namespace object itself is matched by its own name rather
// than its (empty) .metadata.namespace. Cluster-scoped resources of other
// kinds are never filtered by this function.
func FilterExcludedNamespaces(resources []Resource, excluded []string) []Resource {
	if len(excluded) == 0 {
		return resources
	}
	excludeSet := toSet(excluded)

	out := make([]Resource, 0, len(resources))
	for _, r := range resources {
		gvk := r.GVK()
		if gvk.Group == "" && gvk.Kind == "Namespace" {
			if excludeSet[r.Name()] {
				continue
			}
			out = append(out, r)
			continue
		}
		if ns := r.Namespace(); ns != "" && excludeSet[ns] {
			continue
		}
		out = append(out, r)
	}
	return out
}

// FilterSystemRBAC drops Role/ClusterRole/RoleBinding/ClusterRoleBinding
// objects whose name has the "system:" prefix — Kubernetes' own built-in
// RBAC objects (system:controller:*, system:kube-controller-manager, ...).
// They're reserved, cluster-managed, and not something an operator can
// remediate, so by default they're excluded from least-privilege findings.
// Human-controlled bindings like "cluster-admin" or "kubeadm:cluster-admins"
// don't carry this prefix and are unaffected.
func FilterSystemRBAC(resources []Resource) []Resource {
	out := make([]Resource, 0, len(resources))
	for _, r := range resources {
		gvk := r.GVK()
		if gvk.Group == "rbac.authorization.k8s.io" && strings.HasPrefix(r.Name(), "system:") {
			continue
		}
		out = append(out, r)
	}
	return out
}
