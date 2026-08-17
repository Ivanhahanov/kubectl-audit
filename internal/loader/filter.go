package loader

import "strings"

// DefaultExcludedNamespaces are namespaces with no meaningful workloads to
// audit (kube-public holds a public ConfigMap, kube-node-lease only Lease
// objects) — excluded by default purely because there's nothing there to
// find, not as a noise-reduction judgment call. kube-system is
// deliberately NOT in this list: it commonly hosts real, auditable
// third-party infrastructure (CNI, CSI, ...) alongside core Kubernetes
// plumbing, and blanket-excluding the whole namespace would hide genuine
// problems in it, not just the unavoidable ones. The genuinely
// unavoidable violations from core plumbing (kube-proxy needing
// hostNetwork, the kubeadm static control-plane pods, ...) are instead
// handled precisely, per-component, by internal/suppress's built-in
// exceptions — see builtin-exclusions.yaml. Pass --exclude-namespace ""
// or an explicit -n allowlist to override even these two.
var DefaultExcludedNamespaces = []string{"kube-public", "kube-node-lease"}

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
