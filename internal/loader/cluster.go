package loader

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/ivanhahanov/kubectl-audit/internal/k8sclient"
)

// clusterResource describes one kind of object the cluster loader knows how
// to enumerate: its GVR, whether it's namespaced, and a short name used for
// --include-kinds/--exclude-kinds filtering.
type clusterResource struct {
	GVR        schema.GroupVersionResource
	Namespaced bool
	Name       string // e.g. "pods", "deployments", "roles"
}

// defaultResources is the curated set of security-relevant kinds audited by
// default when scanning a live cluster.
var defaultResources = []clusterResource{
	{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}, true, "pods"},
	{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}, true, "services"},
	{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}, false, "namespaces"},
	{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "serviceaccounts"}, true, "serviceaccounts"},
	// ConfigMaps (not Secrets — this tool never reads Secret values, see
	// internal/rbac's broad-secrets-access check, which flags grant breadth
	// instead) are fetched so policies/secrets/*.yaml can flag ConfigMap data
	// that looks like it should have been a Secret.
	{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}, true, "configmaps"},
	{schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, true, "deployments"},
	{schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}, true, "statefulsets"},
	{schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}, true, "daemonsets"},
	{schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}, true, "replicasets"},
	{schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}, true, "jobs"},
	{schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"}, true, "cronjobs"},
	{schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}, true, "roles"},
	{schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}, false, "clusterroles"},
	{schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}, true, "rolebindings"},
	{schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}, false, "clusterrolebindings"},
	{schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}, true, "networkpolicies"},
	{schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"}, true, "ingresses"},
}

// crdResource describes a CRD-backed kind that only exists if the
// corresponding operator/CNI is installed — unlike defaultResources
// (built-in API kinds every cluster serves at a fixed, known version), a
// missing CRD group here is the common case and is skipped silently rather
// than warned about. Deliberately has no Version field: CRD versions (v1
// vs v1beta1/v1beta2/v1alpha1, or a future promotion this tool hasn't been
// updated for yet) are resolved dynamically per-cluster via
// resolvePreferredVersion instead of being hardcoded — the same "ask
// discovery, don't guess" approach kubectl itself uses, so an older or
// newer CRD release than whatever this tool was last tested against still
// gets listed correctly instead of silently returning zero objects.
type crdResource struct {
	Group      string
	Resource   string
	Namespaced bool
	Name       string // e.g. "ciliumnetworkpolicies", for --include-kinds/--exclude-kinds
}

var optionalResources = []crdResource{
	{Group: "cilium.io", Resource: "ciliumnetworkpolicies", Namespaced: true, Name: "ciliumnetworkpolicies"},
	{Group: "cilium.io", Resource: "ciliumclusterwidenetworkpolicies", Namespaced: false, Name: "ciliumclusterwidenetworkpolicies"},
	// crd.projectcalico.org is the CRD-mode storage Calico uses in the
	// overwhelming majority of installs; the alternative aggregated-API-server
	// mode (projectcalico.org/v3, calico-apiserver) is not covered.
	{Group: "crd.projectcalico.org", Resource: "networkpolicies", Namespaced: true, Name: "calico-networkpolicies"},
	{Group: "crd.projectcalico.org", Resource: "globalnetworkpolicies", Namespaced: false, Name: "calico-globalnetworkpolicies"},
	// capsule.clastix.io — see policies/thirdparty/capsule/*.yaml.
	{Group: "capsule.clastix.io", Resource: "tenants", Namespaced: false, Name: "tenants"},
	// security.istio.io — see policies/thirdparty/istio/*.yaml (alpha).
	{Group: "security.istio.io", Resource: "peerauthentications", Namespaced: true, Name: "peerauthentications"},
	{Group: "security.istio.io", Resource: "authorizationpolicies", Namespaced: true, Name: "authorizationpolicies"},
	// argoproj.io — see policies/thirdparty/argocd/*.yaml. AppProject is cluster-scoped.
	{Group: "argoproj.io", Resource: "appprojects", Namespaced: false, Name: "appprojects"},
	// secrets.hashicorp.com (Vault Secrets Operator) — see policies/thirdparty/vault/*.yaml.
	{Group: "secrets.hashicorp.com", Resource: "vaultconnections", Namespaced: true, Name: "vaultconnections"},
	// fluentbit.fluent.io (Fluent Operator) — see policies/thirdparty/fluentbit/*.yaml.
	{Group: "fluentbit.fluent.io", Resource: "outputs", Namespaced: true, Name: "outputs"},
	{Group: "fluentbit.fluent.io", Resource: "clusteroutputs", Namespaced: false, Name: "clusteroutputs"},
	// operator.victoriametrics.com — see policies/thirdparty/victoriametrics/*.yaml.
	{Group: "operator.victoriametrics.com", Resource: "vmsingles", Namespaced: true, Name: "vmsingles"},
	{Group: "operator.victoriametrics.com", Resource: "vmclusters", Namespaced: true, Name: "vmclusters"},
	// postgresql.cnpg.io (CloudNativePG) — see policies/thirdparty/cnpg/*.yaml.
	{Group: "postgresql.cnpg.io", Resource: "clusters", Namespaced: true, Name: "cnpg-clusters"},
}

// ClusterOptions controls which namespaces/kinds are fetched from the cluster.
type ClusterOptions struct {
	Namespaces    []string // empty + AllNamespaces => cluster-wide
	AllNamespaces bool
	IncludeKinds  []string // if set, only these resource names are fetched
	ExcludeKinds  []string
	Source        string // label used on Resource.Source, e.g. "cluster:my-context"
	Warn          func(format string, args ...any)
	// Debug receives routine, expected-most-of-the-time detail not worth
	// a warning by default — e.g. an optional third-party CRD group
	// simply not being registered, the common case for a cluster that
	// doesn't run that component. Nil is a valid no-op default, same as
	// Warn.
	Debug func(format string, args ...any)
}

// LoadCluster enumerates the default (or filtered) set of security-relevant
// resources from a live cluster via the dynamic client, plus any installed
// CNI network-policy CRDs (Cilium, Calico). Individual resource kinds that
// fail to list (e.g. RBAC-denied) produce a warning via opts.Warn and are
// skipped rather than aborting the whole scan.
func LoadCluster(ctx context.Context, c *k8sclient.Client, opts ClusterOptions) ([]Resource, error) {
	warn := opts.Warn
	if warn == nil {
		warn = func(string, ...any) {}
	}
	debug := opts.Debug
	if debug == nil {
		debug = func(string, ...any) {}
	}

	var out []Resource

	for _, r := range filterResources(defaultResources, opts.IncludeKinds, opts.ExcludeKinds) {
		items, err := listResource(ctx, c, r, opts)
		if err != nil {
			warn("skipping %s: %v", r.Name, err)
			continue
		}
		out = append(out, items...)
	}

	for _, r := range filterCRDResources(optionalResources, opts.IncludeKinds, opts.ExcludeKinds) {
		version, ok := resolvePreferredVersion(c, r.Group, r.Name, warn, debug)
		if !ok {
			continue
		}
		gvr := schema.GroupVersionResource{Group: r.Group, Version: version, Resource: r.Resource}
		items, err := listResource(ctx, c, clusterResource{GVR: gvr, Namespaced: r.Namespaced, Name: r.Name}, opts)
		if err != nil {
			warn("skipping %s: %v", r.Name, err)
			continue
		}
		out = append(out, items...)
	}

	return out, nil
}

// listResource fetches every object of one clusterResource, respecting
// namespace scoping. Cluster-scoped kinds ignore namespace options entirely.
func listResource(ctx context.Context, c *k8sclient.Client, r clusterResource, opts ClusterOptions) ([]Resource, error) {
	if !r.Namespaced {
		list, err := c.Dynamic.Resource(r.GVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return toResources(list.Items, opts.Source), nil
	}

	if opts.AllNamespaces || len(opts.Namespaces) == 0 {
		list, err := c.Dynamic.Resource(r.GVR).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return toResources(list.Items, opts.Source), nil
	}

	var out []Resource
	for _, ns := range opts.Namespaces {
		list, err := c.Dynamic.Resource(r.GVR).Namespace(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %s: %w", ns, err)
		}
		out = append(out, toResources(list.Items, opts.Source)...)
	}
	return out, nil
}

func toResources(items []unstructured.Unstructured, source string) []Resource {
	out := make([]Resource, 0, len(items))
	for i := range items {
		out = append(out, Resource{Object: &items[i], Source: source})
	}
	return out
}

// resolvePreferredVersion returns the version the cluster's API server
// actually prefers/serves for group, and false if the group isn't
// registered at all (the common case for an optional CRD-backed kind whose
// operator/CNI isn't installed). This is how the served version is
// determined for every crdResource — never hardcoded — so an older or
// newer CRD release than whatever this tool was last tested against is
// still listed correctly instead of silently returning zero objects.
//
// The two false-returning paths are deliberately not the same signal: a
// ServerGroups() failure is a real discovery-API problem (RBAC-denied,
// API server hiccup) indistinguishable from "not installed" to a caller
// that only sees a bool — surfaced via warn so it isn't silently
// misread as "this component genuinely isn't here" (which matters
// directly for the Detected Components feature's accuracy). The group
// simply not being present in a healthy discovery response is the
// ordinary, expected case for most optional resources on most clusters,
// so it only gets a debug line, not a warning.
func resolvePreferredVersion(c *k8sclient.Client, group, resourceName string, warn, debug func(format string, args ...any)) (string, bool) {
	groups, err := c.Discovery.ServerGroups()
	if err != nil {
		warn("checking whether %s (group %s) is installed: %v", resourceName, group, err)
		return "", false
	}
	for _, g := range groups.Groups {
		if g.Name == group && g.PreferredVersion.Version != "" {
			return g.PreferredVersion.Version, true
		}
	}
	debug("%s: CRD group %s is not registered on this cluster — skipping (component not installed)", resourceName, group)
	return "", false
}

func filterResources(all []clusterResource, include, exclude []string) []clusterResource {
	inSet := toSet(include)
	exSet := toSet(exclude)
	var out []clusterResource
	for _, r := range all {
		if len(inSet) > 0 && !inSet[r.Name] {
			continue
		}
		if exSet[r.Name] {
			continue
		}
		out = append(out, r)
	}
	return out
}

func filterCRDResources(all []crdResource, include, exclude []string) []crdResource {
	inSet := toSet(include)
	exSet := toSet(exclude)
	var out []crdResource
	for _, r := range all {
		if len(inSet) > 0 && !inSet[r.Name] {
			continue
		}
		if exSet[r.Name] {
			continue
		}
		out = append(out, r)
	}
	return out
}

func toSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, i := range items {
		s[strings.ToLower(i)] = true
	}
	return s
}

// SourceLabel builds the Resource.Source string for cluster-origin resources.
func SourceLabel(context string) string {
	if context == "" {
		return "cluster:current-context"
	}
	return fmt.Sprintf("cluster:%s", context)
}
