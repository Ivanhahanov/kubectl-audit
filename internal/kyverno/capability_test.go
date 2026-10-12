package kyverno_test

import (
	"context"
	"errors"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/ivanhahanov/kubectl-audit/internal/kyverno"
)

type fakeRESTMapping struct {
	found bool
	err   error
}

func (f fakeRESTMapping) RESTMapping(gk schema.GroupKind, versions ...string) (*meta.RESTMapping, error) {
	if f.err != nil {
		return nil, f.err
	}
	if !f.found {
		return nil, &meta.NoKindMatchError{GroupKind: gk}
	}
	return &meta.RESTMapping{}, nil
}

func TestDetectValidatingPolicySupport_Found(t *testing.T) {
	ok, err := kyverno.DetectValidatingPolicySupport(fakeRESTMapping{found: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected true when the RESTMapper resolves the Kind")
	}
}

func TestDetectValidatingPolicySupport_NotFound(t *testing.T) {
	ok, err := kyverno.DetectValidatingPolicySupport(fakeRESTMapping{found: false})
	if err != nil {
		t.Fatalf("expected a NoKindMatchError to resolve to (false, nil), got error: %v", err)
	}
	if ok {
		t.Error("expected false when the CRD isn't registered")
	}
}

func TestDetectValidatingPolicySupport_OtherErrorPropagates(t *testing.T) {
	_, err := kyverno.DetectValidatingPolicySupport(fakeRESTMapping{err: errors.New("boom")})
	if err == nil {
		t.Error("expected a genuine RESTMapper error to propagate, not be swallowed as \"not found\"")
	}
}

func TestDetectClusterPolicyCELSupport_CELFieldPresent(t *testing.T) {
	crd := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"metadata":   map[string]any{"name": "clusterpolicies.kyverno.io"},
		"spec": map[string]any{
			"versions": []any{
				map[string]any{
					"schema": map[string]any{
						"openAPIV3Schema": map[string]any{
							"properties": map[string]any{
								"spec": map[string]any{
									"properties": map[string]any{
										"rules": map[string]any{
											"items": map[string]any{
												"properties": map[string]any{
													"validate": map[string]any{
														"properties": map[string]any{
															"cel": map[string]any{"description": "CEL block"},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}}
	scheme := runtime.NewScheme()
	gvrToKind := map[schema.GroupVersionResource]string{
		{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}: "CustomResourceDefinitionList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToKind, crd)

	ok, err := kyverno.DetectClusterPolicyCELSupport(context.Background(), dyn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected true when the CRD schema contains a \"cel\" property")
	}
}

func TestDetectClusterPolicyCELSupport_NoCELField(t *testing.T) {
	crd := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"metadata":   map[string]any{"name": "clusterpolicies.kyverno.io"},
		"spec": map[string]any{
			"versions": []any{
				map[string]any{"name": "v1"},
			},
		},
	}}
	scheme := runtime.NewScheme()
	gvrToKind := map[schema.GroupVersionResource]string{
		{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}: "CustomResourceDefinitionList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToKind, crd)

	ok, err := kyverno.DetectClusterPolicyCELSupport(context.Background(), dyn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected false when the CRD schema has no \"cel\" property (pre-CEL Kyverno)")
	}
}

func TestDetectClusterPolicyCELSupport_CRDNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	gvrToKind := map[schema.GroupVersionResource]string{
		{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}: "CustomResourceDefinitionList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToKind)

	ok, err := kyverno.DetectClusterPolicyCELSupport(context.Background(), dyn)
	if err != nil {
		t.Fatalf("expected a NotFound CRD to resolve to (false, nil), got error: %v", err)
	}
	if ok {
		t.Error("expected false when the clusterpolicies.kyverno.io CRD doesn't exist at all")
	}
}
