// Package k8sclient resolves kubeconfig/context and builds the
// discovery + dynamic clients used to read resources from a live cluster.
package k8sclient

import (
	"fmt"

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
// ~/.kube/config) and builds a Client.
func New(kubeconfigPath, contextName string) (*Client, error) {
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
