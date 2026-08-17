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
	// Tenant is Capsule's (github.com/projectcapsule/capsule) multi-tenancy
	// CRD, capsule.clastix.io/v1beta2 — see policies/thirdparty/capsule/*.yaml.
	"Tenant": "tenants",
	// Istio security.istio.io/networking.istio.io CRDs — see
	// policies/thirdparty/istio/*.yaml (alpha). "Gateway" also exists as a Kind in
	// the standard gateway.networking.k8s.io Gateway API, sharing the same
	// plural "gateways" — harmless, since matchConstraints.apiGroups still
	// scopes each policy to the correct group.
	"PeerAuthentication":  "peerauthentications",
	"AuthorizationPolicy": "authorizationpolicies",
	"DestinationRule":     "destinationrules",
	"Gateway":             "gateways",
	"Sidecar":             "sidecars",
	// ArgoCD argoproj.io/v1alpha1 CRDs — see policies/thirdparty/argocd/*.yaml.
	"AppProject":  "appprojects",
	"Application": "applications",
	// HashiCorp Vault Secrets Operator secrets.hashicorp.com/v1beta1 CRDs —
	// see policies/thirdparty/vault/*.yaml.
	"VaultConnection": "vaultconnections",
	"VaultAuth":       "vaultauths",
	// Fluent Operator fluentbit.fluent.io/v1alpha2 CRDs — see
	// policies/thirdparty/fluentbit/*.yaml. Output is namespaced, ClusterOutput is
	// cluster-scoped; both share the same spec shape.
	"Output":        "outputs",
	"ClusterOutput": "clusteroutputs",
	// VictoriaMetrics Operator operator.victoriametrics.com/v1beta1 CRDs —
	// see policies/thirdparty/victoriametrics/*.yaml.
	"VMSingle":  "vmsingles",
	"VMCluster": "vmclusters",
	"VMAuth":    "vmauths",
	"VMAgent":   "vmagents",
	// CloudNativePG postgresql.cnpg.io/v1 CRD — see policies/thirdparty/cnpg/*.yaml.
	"Cluster": "clusters",
	// Kyverno kyverno.io CRDs — see policies/thirdparty/kyverno/*.yaml. ClusterPolicy
	// is cluster-scoped, Policy is namespaced; both share the same spec
	// shape.
	"ClusterPolicy": "clusterpolicies",
	"Policy":        "policies",
	// Calico crd.projectcalico.org CRD — see policies/thirdparty/calico/*.yaml.
	"FelixConfiguration": "felixconfigurations",
	// APISIX apisix.apache.org/v2 CRD (apisix-ingress-controller) — see
	// policies/thirdparty/apisix/*.yaml. Verified against
	// config/crd/bases/apisix.apache.org_apisixtlses.yaml.
	"ApisixTls": "apisixtlses",
	// KubeVirt kubevirt.io CRDs — see policies/thirdparty/kubevirt/*.yaml.
	// KubeVirt is the operator's own cluster-wide config singleton;
	// VirtualMachine/VirtualMachineInstance share the same volumes[]
	// shape (the latter nested under .spec.template.spec on the former).
	"KubeVirt":               "kubevirts",
	"VirtualMachine":         "virtualmachines",
	"VirtualMachineInstance": "virtualmachineinstances",
}

// ResourceNameForKind returns the plural resource name for a known Kind.
func ResourceNameForKind(kind string) (string, bool) {
	r, ok := kindToResource[kind]
	return r, ok
}

// knownResources is the set of every plural resource name kindToResource
// maps to, built once at package init. IsKnownResource uses it to answer
// "does at least one registered Kind resolve to this resource" — the
// reverse direction of ResourceNameForKind, used by
// engine.Matches/kindToResource's consumers to catch a policy that targets
// a resource name no loaded object could ever carry.
var knownResources = func() map[string]bool {
	set := make(map[string]bool, len(kindToResource))
	for _, r := range kindToResource {
		set[r] = true
	}
	return set
}()

// IsKnownResource reports whether at least one Kind registered in
// kindToResource maps to this plural resource name. A policy whose
// matchConstraints.resourceRules names a resource for which this is false
// can never match any resource loaded from a cluster or static manifest —
// engine.Matches resolves every loaded object's Kind to a resource name via
// ResourceNameForKind before comparing it against a policy's resources
// list, so an object of an unregistered Kind never even reaches that
// comparison.
func IsKnownResource(resource string) bool {
	return knownResources[resource]
}
