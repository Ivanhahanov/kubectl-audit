// Package k8sclient resolves kubeconfig/context and builds the
// discovery + dynamic clients used to read resources from a live cluster.
package k8sclient

import (
	"fmt"
	"time"

	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
)

// Client bundles the dynamic and discovery clients needed to enumerate and
// read arbitrary resources from a cluster.
type Client struct {
	Dynamic    dynamic.Interface
	Discovery  discovery.DiscoveryInterface
	RESTMapper *restmapper.DeferredDiscoveryRESTMapper
	Config     *rest.Config
	Context    string
}

// New resolves the kubeconfig (respecting an explicit path and/or context
// override, falling back to the standard loading rules: $KUBECONFIG, then
// ~/.kube/config) and builds a Client. timeout bounds every individual
// request made through the resulting Dynamic/Discovery clients (rest.
// Config.Timeout — applied per-request, not as one deadline for the whole
// scan); timeout<=0 disables it, restoring the pre-timeout behavior of
// however long the apiserver takes. This tool only ever does one-shot
// List/Get calls, never a Watch, so a flat per-request timeout can't cut
// off a legitimately long-lived call.
func New(kubeconfigPath, contextName string, timeout time.Duration) (*Client, error) {
	overrides := &genericclioptions.ConfigFlags{}
	if kubeconfigPath != "" {
		overrides.KubeConfig = &kubeconfigPath
	}
	if contextName != "" {
		overrides.Context = &contextName
	}

	restCfg, err := overrides.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("resolving kubeconfig: %w", err)
	}
	if timeout > 0 {
		restCfg.Timeout = timeout
	}

	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("building dynamic client: %w", err)
	}
	disc, err := discovery.NewDiscoveryClientForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("building discovery client: %w", err)
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(disc))

	return &Client{
		Dynamic:    dyn,
		Discovery:  disc,
		RESTMapper: mapper,
		Config:     restCfg,
		Context:    contextName,
	}, nil
}
