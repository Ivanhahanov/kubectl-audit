package loader

// kindToResource maps a Kind to its plural resource name, used to evaluate
// VAP-style matchConstraints.resourceRules (which are expressed in terms of
// resources, not kinds) against resources loaded from either the cluster or
// static manifests.
var kindToResource = map[string]string{
	"Pod":                   "pods",
	"Service":               "services",
	"Namespace":             "namespaces",
	"ServiceAccount":        "serviceaccounts",
	"ConfigMap":             "configmaps",
	"Secret":                "secrets",
	"Node":                  "nodes",
	"PersistentVolumeClaim": "persistentvolumeclaims",
	"ReplicationController": "replicationcontrollers",
	"Deployment":            "deployments",
	"StatefulSet":           "statefulsets",
	"DaemonSet":             "daemonsets",
	"ReplicaSet":            "replicasets",
	"Job":                   "jobs",
	"CronJob":               "cronjobs",
	"Role":                  "roles",
	"ClusterRole":           "clusterroles",
	"RoleBinding":           "rolebindings",
	"ClusterRoleBinding":    "clusterrolebindings",
	"NetworkPolicy":         "networkpolicies",
	"Ingress":               "ingresses",
}

// ResourceNameForKind returns the plural resource name for a known Kind.
func ResourceNameForKind(kind string) (string, bool) {
	r, ok := kindToResource[kind]
	return r, ok
}
