package kyverno

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// restMappingFinder is the one additional restmapper method (beyond KindFor,
// see KindResolver) this file needs — narrowed the same way for the same
// reason: independent of client-go's discovery machinery in this package's
// own API, trivially fakeable in tests.
type restMappingFinder interface {
	RESTMapping(gk schema.GroupKind, versions ...string) (*meta.RESTMapping, error)
}

// DetectValidatingPolicySupport reports whether the target cluster has
// Kyverno's policies.kyverno.io ValidatingPolicy CRD installed at all
// (Kyverno 1.13+) — resolved through the RESTMapper, which only succeeds
// if the CRD is actually registered on this cluster, never guessed from a
// Kyverno version string (there is no reliable way to read "the Kyverno
// version" generically — install method, namespace, and deployment names
// all vary — so this checks the one thing that actually determines
// whether `kubectl apply` will work: does the Kind exist at all).
func DetectValidatingPolicySupport(mapper restMappingFinder) (bool, error) {
	_, err := mapper.RESTMapping(schema.GroupKind{Group: "policies.kyverno.io", Kind: "ValidatingPolicy"})
	if err != nil {
		if meta.IsNoMatchError(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// DetectClusterPolicyCELSupport reports whether this cluster's
// clusterpolicies.kyverno.io CRD schema accepts CEL expressions under
// validate (Kyverno 1.11+) — checked by fetching the live CRD object and
// looking for a literal "cel" property in its schema, not by guessing from
// a version number. This matters because the CRD existing at all proves
// nothing: ClusterPolicy has existed since Kyverno's first release, long
// before CEL support — applying validate.cel.expressions against an older
// CRD schema doesn't error, it just silently drops the unrecognized field
// (structural-schema pruning), leaving a ClusterPolicy that applies
// cleanly and enforces nothing at all. A substring check rather than
// walking the exact nested schema path, since that path has shifted
// slightly across Kyverno releases — a false positive is effectively
// impossible (no unrelated field is named "cel"), so this stays safe
// either way.
func DetectClusterPolicyCELSupport(ctx context.Context, dyn dynamic.Interface) (bool, error) {
	gvr := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	crd, err := dyn.Resource(gvr).Get(ctx, "clusterpolicies.kyverno.io", metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("fetching clusterpolicies.kyverno.io CRD: %w", err)
	}
	data, err := json.Marshal(crd.Object)
	if err != nil {
		return false, fmt.Errorf("marshaling clusterpolicies.kyverno.io CRD: %w", err)
	}
	return strings.Contains(string(data), `"cel":`), nil
}
