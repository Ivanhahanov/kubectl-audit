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

// optionalResources are CRD-backed kinds that only exist if the cluster has
// the corresponding CNI installed. Unlike defaultResources, a missing CRD
// here is the common case (most clusters run neither Cilium nor Calico) and
// is skipped silently rather than warned about; see gvrRegistered.
var optionalResources = []clusterResource{
	{schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}, true, "ciliumnetworkpolicies"},
	{schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"}, false, "ciliumclusterwidenetworkpolicies"},
	// crd.projectcalico.org/v1 is the CRD-mode storage Calico uses in the
	// overwhelming majority of installs; the alternative aggregated-API-server
	// mode (projectcalico.org/v3, calico-apiserver) is not covered.
	{schema.GroupVersionResource{Group: "crd.projectcalico.org", Version: "v1", Resource: "networkpolicies"}, true, "calico-networkpolicies"},
	{schema.GroupVersionResource{Group: "crd.projectcalico.org", Version: "v1", Resource: "globalnetworkpolicies"}, false, "calico-globalnetworkpolicies"},
}

// ClusterOptions controls which namespaces/kinds are fetched from the cluster.
type ClusterOptions struct {
	Namespaces    []string // empty + AllNamespaces => cluster-wide
	AllNamespaces bool
	IncludeKinds  []string // if set, only these resource names are fetched
	ExcludeKinds  []string
	Source        string // label used on Resource.Source, e.g. "cluster:my-context"
	Warn          func(format string, args ...any)
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

	var out []Resource

	for _, r := range filterResources(defaultResources, opts.IncludeKinds, opts.ExcludeKinds) {
		items, err := listResource(ctx, c, r, opts)
		if err != nil {
			warn("skipping %s: %v", r.Name, err)
			continue
		}
		out = append(out, items...)
	}

	for _, r := range filterResources(optionalResources, opts.IncludeKinds, opts.ExcludeKinds) {
		if !gvrRegistered(c, r.GVR) {
			continue
		}
		items, err := listResource(ctx, c, r, opts)
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

// gvrRegistered reports whether a GroupVersionResource is served by the
// cluster's API server, used to decide whether to even attempt listing an
// optional CRD-backed kind.
func gvrRegistered(c *k8sclient.Client, gvr schema.GroupVersionResource) bool {
	resourceList, err := c.Discovery.ServerResourcesForGroupVersion(gvr.GroupVersion().String())
	if err != nil {
		return false
	}
	for _, res := range resourceList.APIResources {
		if res.Name == gvr.Resource {
			return true
		}
	}
	return false
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
