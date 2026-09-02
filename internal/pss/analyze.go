// Package pss checks every workload against the official Kubernetes Pod
// Security Standards (Baseline and Restricted profiles), using
// k8s.io/pod-security-admission/policy directly — the same check
// implementations the Pod Security Admission controller itself runs. This
// is deliberately not a reimplementation of the PSS rules in CEL: getting
// every detail right by hand (e.g. exactly which capabilities Baseline
// still allows adding, the Sysctls safe-list, seccomp/AppArmor/SELinux
// nuances) is exactly the kind of thing the upstream library is the
// canonical source of truth for, and stays correct as Kubernetes evolves.
//
// This is a different, complementary signal to the bundled workload.*
// policies: those map to specific numbered CIS controls one at a time,
// while this package answers one aggregate question Kubernetes itself
// defines an authoritative answer for — "does this pod comply with
// Baseline/Restricted" — which is also useful as a shift-left check on
// static manifests before they ever reach a cluster, independent of
// whether that cluster actually enforces Pod Security Admission.
package pss

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	psaapi "k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/k8sversion"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// Check IDs: exactly one of these fires per workload, whichever is the
// lowest level it fails (see Analyze) — a Baseline failure implies further,
// redundant Restricted failures that would just add noise without new
// information.
const (
	CheckIDBaseline   = "pss-analyzer.baseline"
	CheckIDRestricted = "pss-analyzer.restricted"
)

// Analyze evaluates every Pod-shaped workload against the official Pod
// Security Standards Baseline and Restricted profiles.
//
// k8sVersion is the detected cluster's version (e.g. "v1.27.16", as
// returned by client-go's discovery client) — pod-security-admission's own
// check implementations are versioned (the Restricted capabilities rule
// changed at 1.22 and again at 1.25; ProcMount checks only exist from 1.35
// onward), so evaluating an old cluster against "latest" rules can apply
// requirements that didn't exist yet for that version. An empty or
// unparseable k8sVersion (a static-manifest-only scan with no live cluster
// to ask) falls back to the newest version this build knows about.
func Analyze(resources []loader.Resource, source, k8sVersion string, warn func(format string, args ...any)) ([]findings.Finding, error) {
	if warn == nil {
		warn = func(string, ...any) {}
	}
	version := resolveVersion(k8sVersion)
	evaluator, err := policy.NewEvaluator(policy.DefaultChecks(), &version)
	if err != nil {
		return nil, fmt.Errorf("initializing Pod Security Standards evaluator: %w", err)
	}

	var out []findings.Finding
	for _, r := range resources {
		meta, spec, ok := podTemplateOf(r, warn)
		if !ok {
			continue
		}

		ref := findings.ResourceRef{
			APIVersion: r.GVK().GroupVersion().String(),
			Kind:       r.GVK().Kind,
			Namespace:  r.Namespace(),
			Name:       r.Name(),
		}

		baseline := policy.AggregateCheckResults(evaluator.EvaluatePod(
			psaapi.LevelVersion{Level: psaapi.LevelBaseline, Version: version}, meta, spec))
		if !baseline.Allowed {
			out = append(out, finding(CheckIDBaseline, "baseline", baseline, ref, r.Source))
			continue // Restricted would just repeat (a superset of) these reasons.
		}

		restricted := policy.AggregateCheckResults(evaluator.EvaluatePod(
			psaapi.LevelVersion{Level: psaapi.LevelRestricted, Version: version}, meta, spec))
		if !restricted.Allowed {
			out = append(out, finding(CheckIDRestricted, "restricted", restricted, ref, r.Source))
		}
	}
	return out, nil
}

func resolveVersion(k8sVersion string) psaapi.Version {
	major, minor, ok := k8sversion.Parse(k8sVersion)
	if !ok {
		return psaapi.LatestVersion()
	}
	return psaapi.MajorMinorVersion(major, minor)
}

func finding(checkID, level string, result policy.AggregateCheckResult, ref findings.ResourceRef, source string) findings.Finding {
	sev := findings.SeverityMedium
	if level == "baseline" {
		sev = findings.SeverityHigh
	}
	// ForbiddenDetail() already interleaves each reason with its own detail
	// in parens (e.g. "host ports (8080, 9090), privileged containers") —
	// concatenating it after ForbiddenReason() would repeat every reason
	// twice.
	msg := fmt.Sprintf("Does not satisfy the Pod Security Standards %q profile: %s", level, result.ForbiddenDetail())
	return findings.Finding{
		ID:       findings.NewID(checkID, ref),
		PolicyID: checkID,
		Title:    fmt.Sprintf("Workload fails the Pod Security Standards %q profile", level),
		Severity: sev,
		Category: "workload-security",
		Resource: ref,
		Message:  msg,
		// DedupKey groups by which rules were violated (ForbiddenReason —
		// no per-container/port/capability parenthetical detail), not the
		// full Message. On a cluster with many unrelated tenant workloads
		// each independently missing the same securityContext field, the
		// container name alone in ForbiddenDetail() was enough to keep
		// every one of them from collapsing in the triage TUI, even though
		// "which rule is violated" — not which container — is the useful
		// bulk-triage signal here. See findings.Finding.DedupKey.
		DedupKey: checkID + "|" + result.ForbiddenReason(),
		Remediation: fmt.Sprintf(
			"See https://kubernetes.io/docs/concepts/security/pod-security-standards/#%s for the full %s profile requirements.",
			level, level),
		VerificationSteps: "1. Read the specific forbidden reasons in the Message (e.g. \"privileged\", " +
			"\"hostNetwork\", \"runAsNonRoot != true\") — each maps to one documented Pod Security Standards " +
			"rule at the Remediation link; confirm which literal field in the Pod/container spec actually " +
			"triggered it. 2. Check whether an admission controller (real Pod Security Admission with an " +
			"enforce label, Kyverno, OPA/Gatekeeper) already blocks this in the live cluster — if so, this is " +
			"an audit-only finding on a manifest that couldn't actually be applied as-is, still worth fixing " +
			"but not an active running risk. 3. Check the report's Detected Components table for a documented, " +
			"expected exception (e.g. a CNI/storage DaemonSet needing hostNetwork) before treating this as a " +
			"straightforward app-team fix.",
		Source: source,
	}
}

// podTemplateOf extracts the pod template (metadata + spec) a workload
// resource produces: itself for a bare Pod, spec.template for
// Deployment/StatefulSet/DaemonSet/ReplicaSet/Job, and
// spec.jobTemplate.spec.template for a CronJob.
//
// warn is called when a resource is a recognized pod-template-bearing kind
// but its spec fails to convert (e.g. a field with the wrong type, such as
// runAsUser written as a YAML string instead of an integer) — previously
// this was a silent skip with zero diagnostic signal anywhere, even in -v
// mode, found by an adversarial audit. A resource whose kind isn't
// pod-template-bearing at all (a ConfigMap, a Service, ...) is the normal,
// expected case and does not warn.
func podTemplateOf(r loader.Resource, warn func(format string, args ...any)) (*metav1.ObjectMeta, *corev1.PodSpec, bool) {
	gvk := r.GVK()
	switch {
	case gvk.Group == "" && gvk.Kind == "Pod":
		var pod corev1.Pod
		if err := convert(r, &pod); err != nil {
			warn("pss: skipping %s %s/%s — %v", gvk.Kind, r.Namespace(), r.Name(), err)
			return nil, nil, false
		}
		return &pod.ObjectMeta, &pod.Spec, true

	case isPodTemplateController(gvk):
		var holder struct {
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := convert(r, &holder); err != nil {
			warn("pss: skipping %s %s/%s — %v", gvk.Kind, r.Namespace(), r.Name(), err)
			return nil, nil, false
		}
		return &holder.Spec.Template.ObjectMeta, &holder.Spec.Template.Spec, true

	case gvk.Group == "batch" && gvk.Kind == "CronJob":
		var holder struct {
			Spec struct {
				JobTemplate struct {
					Spec struct {
						Template corev1.PodTemplateSpec `json:"template"`
					} `json:"spec"`
				} `json:"jobTemplate"`
			} `json:"spec"`
		}
		if err := convert(r, &holder); err != nil {
			warn("pss: skipping %s %s/%s — %v", gvk.Kind, r.Namespace(), r.Name(), err)
			return nil, nil, false
		}
		return &holder.Spec.JobTemplate.Spec.Template.ObjectMeta, &holder.Spec.JobTemplate.Spec.Template.Spec, true
	}
	return nil, nil, false
}

func isPodTemplateController(gvk schema.GroupVersionKind) bool {
	switch gvk.Group {
	case "apps":
		switch gvk.Kind {
		case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet":
			return true
		}
	case "batch":
		return gvk.Kind == "Job"
	}
	return false
}

func convert(r loader.Resource, out interface{}) error {
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(r.Object.Object, out); err != nil {
		return fmt.Errorf("converting %s %s: %w", r.GVK().Kind, r.Name(), err)
	}
	return nil
}
