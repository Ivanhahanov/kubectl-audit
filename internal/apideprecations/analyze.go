// Package apideprecations flags manifests using a Kubernetes API version
// that's been fully removed (not merely deprecated-but-still-working) —
// meaning the manifest would be rejected outright if applied to a cluster
// at or above the version that removed it.
//
// This needs no hand-maintained table and no network call: it reads the
// removal metadata Kubernetes' own release tooling (prerelease-lifecycle-gen)
// generates directly onto the Go types in k8s.io/api — every type that's
// ever been removed has generated APILifecycleRemoved()/
// APILifecycleReplacement() methods (see e.g.
// k8s.io/api/extensions/v1beta1/zz_generated.prerelease-lifecycle.go);
// types that were never removed simply don't implement that interface, so
// a failed type assertion below is exactly the "not removed" signal, no
// sentinel value needed. k8s.io/client-go/kubernetes/scheme registers every
// historical group/version (including long-removed ones like
// extensions/v1beta1) specifically so old manifests/clients keep working
// with tooling like this, which is what makes constructing an instance by
// GVK below possible.
//
// This means the data is exactly as fresh as the k8s.io/api version this
// binary was built against — bumping that dependency (routine maintenance,
// done for other reasons anyway) picks up whatever new removals shipped in
// the meantime, with no separate table to hand-edit. See
// k8sversion.LatestKnownMinor for the freshness self-check this relies on.
package apideprecations

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/k8sversion"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

const CheckID = "apideprecations.removed-api"

// lifecycleRemoved/lifecycleReplacement are implemented by the generated
// zz_generated.prerelease-lifecycle.go methods on k8s.io/api types that
// have actually been removed at some point — see the package doc comment.
type lifecycleRemoved interface {
	APILifecycleRemoved() (major, minor int)
}

type lifecycleReplacement interface {
	APILifecycleReplacement() schema.GroupVersionKind
}

// Analyze flags every resource whose declared apiVersion+Kind has ever been
// removed from Kubernetes, at or before the target version. k8sVersion is
// the detected cluster's GitVersion (e.g. "v1.27.16"); an empty or
// unparseable value (a static-manifest-only scan with no live cluster to
// check against) falls back to k8sversion.LatestKnownMajor/Minor — the
// reasonable default for "will this manifest work on a current cluster."
func Analyze(resources []loader.Resource, k8sVersion, source string) []findings.Finding {
	major, minor, ok := k8sversion.Parse(k8sVersion)
	if !ok {
		major, minor = k8sversion.LatestKnownMajor, k8sversion.LatestKnownMinor
	}

	var out []findings.Finding
	for _, r := range resources {
		gvk := r.GVK()
		obj, err := scheme.Scheme.New(gvk)
		if err != nil {
			continue // not a built-in type this scheme knows about (e.g. a CRD) — nothing to say
		}
		lr, ok := obj.(lifecycleRemoved)
		if !ok {
			continue // never removed
		}
		remMajor, remMinor := lr.APILifecycleRemoved()

		replacement := "a current API version (see the official deprecation guide)"
		if lrep, ok := obj.(lifecycleReplacement); ok {
			if rg := lrep.APILifecycleReplacement(); rg.Kind != "" {
				replacement = rg.GroupVersion().String()
			}
		}

		ref := findings.ResourceRef{
			APIVersion: gvk.GroupVersion().String(),
			Kind:       gvk.Kind,
			Namespace:  r.Namespace(),
			Name:       r.Name(),
		}

		var sev findings.Severity
		var msg string
		if versionAtLeast(major, minor, remMajor, remMinor) {
			sev = findings.SeverityCritical
			msg = fmt.Sprintf(
				"%s %s was removed in Kubernetes v%d.%d and can no longer be applied to a cluster at or above that version. Migrate to %s.",
				ref.APIVersion, gvk.Kind, remMajor, remMinor, replacement)
		} else {
			sev = findings.SeverityHigh
			msg = fmt.Sprintf(
				"%s %s still works on the detected/target Kubernetes version, but was removed in v%d.%d — it will break on upgrade past that. Migrate to %s.",
				ref.APIVersion, gvk.Kind, remMajor, remMinor, replacement)
		}

		out = append(out, findings.Finding{
			ID:          findings.NewID(CheckID, ref),
			PolicyID:    CheckID,
			Title:       "Manifest uses a removed Kubernetes API version",
			Severity:    sev,
			Category:    "patch-lifecycle",
			Resource:    ref,
			Message:     msg,
			Remediation: fmt.Sprintf("Update apiVersion to %s.", replacement),
			VerificationSteps: "1. Confirm this is the actual apiVersion in the live source (a GitOps-tracked " +
				"manifest could already be fixed upstream but not yet re-scanned). 2. If this object comes " +
				"from a Helm chart/operator you don't hand-author, check whether a newer chart version already " +
				"emits the replacement apiVersion — the real fix may be a version bump, not a manual edit. " +
				"3. If marked critical (already removed on this cluster's version), confirm the apiserver " +
				"genuinely rejects it: `kubectl apply --dry-run=server -f <file>` against a real cluster.",
			Source: r.Source,
		})
	}
	return out
}

// StaleWarning returns a non-empty message if the detected cluster version
// is far enough ahead of this build's k8s.io/api version (approximated by
// k8sversion.LatestKnownMajor/Minor, which is kept in step with it) that
// Analyze risks not knowing about a removal batch that shipped since —
// bumping the k8s.io/api dependency is what refreshes this, there's no
// separate table to re-verify by hand.
func StaleWarning(k8sVersion string) string {
	major, minor, ok := k8sversion.Parse(k8sVersion)
	if !ok || major != k8sversion.LatestKnownMajor {
		return ""
	}
	const driftTolerance = 3
	if minor-k8sversion.LatestKnownMinor <= driftTolerance {
		return ""
	}
	return fmt.Sprintf(
		"this build's Kubernetes API removal data (from its k8s.io/api dependency, v%d.%d) may not know about removals from newer releases — this cluster is on v%d.%d, %d minor versions ahead. Update kubectl-audit to pick up a newer k8s.io/api.",
		k8sversion.LatestKnownMajor, k8sversion.LatestKnownMinor, major, minor, minor-k8sversion.LatestKnownMinor)
}

func versionAtLeast(major, minor, wantMajor, wantMinor int) bool {
	if major != wantMajor {
		return major > wantMajor
	}
	return minor >= wantMinor
}
