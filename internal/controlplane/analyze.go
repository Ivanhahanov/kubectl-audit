// Package controlplane looks for control-plane static Pods (kube-apiserver,
// kube-controller-manager, kube-scheduler, etcd) among the scanned resources
// and evaluates their command-line flags against the CIS Kubernetes
// Benchmark's Section 1 (Control Plane Components), Section 2 (etcd), and
// Section 3.2 (audit policy presence) recommendations.
//
// This is an INDIRECT, best-effort signal, not a substitute for kube-bench.
// Self-hosted/kubeadm-style clusters (including kind) run these components
// as ordinary Pods, visible via the Kubernetes API the same way any other
// Pod spec is — typically in kube-system, labeled component=kube-apiserver
// etc. Managed control planes (EKS, GKE, AKS, ...) don't expose these Pods
// at all; when a component isn't found, this package simply produces no
// findings for it, and the caller is expected to mark the corresponding
// compliance controls NOT_APPLICABLE for the run (see
// compliance.OverrideUnobserved) instead of reporting a false PASS.
//
// Every finding it produces says explicitly that it's an indirect signal:
// this reflects what a flag is *set to* in the Pod spec, not whether the
// setting is actually effective (a process restart with different args, a
// distro-specific default, or drift between the manifest and the running
// process could all make this wrong). parseFlags recognizes both the
// "--flag=value" form kubeadm always uses and the rarer space-separated
// "--flag value" form (two consecutive args-list elements) some non-kubeadm
// distros use — a prior version of this doc comment claimed the latter
// "is not parsed", implying a silent miss, but the real prior behavior was
// worse: it registered as flag="true" (an ambiguous boolean marker) and
// could produce an active, wrong-value false positive on a correctly
// configured flag (found and fixed after an adversarial audit).
//
// The simpler sibling checks in policies/controlplane/*.yaml (CEL,
// VAPCheckIDPrefix) do NOT share this space-separated-form handling: their
// base CEL environment (internal/engine's newBaseEnv, deliberately kept
// close to what a real Kubernetes ValidatingAdmissionPolicy CEL environment
// offers, so these stay usable as real enforceable policies) has no
// index-based list access or lookahead, only per-element macros
// (exists/all/map/filter) — there's no way to express "the element right
// after this one" without it. This is a real, permanent scope limitation of
// the CEL checks, not an oversight: it's why every numeric-threshold,
// CSV-membership, or cross-flag check (audit-log-maxage, admission-plugins,
// authorization-mode, ...) lives here in Go instead, and the CEL policies
// are deliberately limited to simple "--flag=value" presence/exact-match
// checks, where a missed space-separated form is a false negative on an
// already-lower-consequence check rather than the wrong-value false
// positive the Go side could previously produce.
package controlplane

import (
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// Component names: the second segment of every check ID (e.g.
// "controlplane-analyzer.apiserver.profiling") and the keys of the Observed
// map Analyze returns.
const (
	ComponentAPIServer         = "apiserver"
	ComponentControllerManager = "controller-manager"
	ComponentScheduler         = "scheduler"
	ComponentEtcd              = "etcd"
)

// CheckIDPrefix is the common prefix of every native check ID this package
// emits, used by compliance.OverrideUnobserved to recognize them.
const CheckIDPrefix = "controlplane-analyzer."

// VAPCheckIDPrefix is the common prefix of the VAP/CEL policy IDs in
// policies/controlplane/*.yaml — the simpler flag checks that don't need
// Go's CSV-membership/cross-flag/numeric-threshold logic. Same naming
// convention ("<prefix><component>.<check-name>"), same
// compliance.OverrideUnobserved fallback, different mechanism.
const VAPCheckIDPrefix = "controlplane."

// flags is a parsed view of a container's command-line flags; repeated
// flags keep every value, in the order seen.
type flags map[string][]string

// last returns a flag's last-set value (CLI convention: later wins), or
// ("", false) if it was never set.
func (f flags) last(name string) (string, bool) {
	vals := f[name]
	if len(vals) == 0 {
		return "", false
	}
	return vals[len(vals)-1], true
}

func (f flags) isSet(name string) bool {
	_, ok := f.last(name)
	return ok
}

func (f flags) equals(name, want string) bool {
	v, ok := f.last(name)
	return ok && v == want
}

func (f flags) csvContains(name, item string) bool {
	v, ok := f.last(name)
	if !ok {
		return false
	}
	for _, part := range strings.Split(v, ",") {
		if strings.TrimSpace(part) == item {
			return true
		}
	}
	return false
}

func (f flags) atLeast(name string, min int) bool {
	v, ok := f.last(name)
	if !ok {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	return err == nil && n >= min
}

// parseFlags reads a container's Command+Args for "--flag=value" arguments.
// Static pod manifests generated by kubeadm always use this form; the
// binary name (conventionally Command[0]) and any other non-flag argument
// are ignored.
func parseFlags(command, args []string) flags {
	out := flags{}
	items := make([]string, 0, len(command)+len(args))
	items = append(items, command...)
	items = append(items, args...)
	for i := 0; i < len(items); i++ {
		item := items[i]
		if !strings.HasPrefix(item, "--") {
			continue
		}
		item = strings.TrimPrefix(item, "--")
		if idx := strings.IndexByte(item, '='); idx >= 0 {
			out[item[:idx]] = append(out[item[:idx]], item[idx+1:])
			continue
		}
		// No "=" on this element: either a bare boolean flag
		// (--profiling, a real, valid container-arg style with no
		// explicit value) or the space-separated form (--flag value, as
		// two list elements — also real and valid: a YAML args: list can
		// legally write either style, and static pods in the wild use
		// both). Distinguishing them: if the NEXT element exists and
		// isn't itself another flag, it's this flag's value — consume it
		// rather than defaulting to "true", which previously produced
		// active, wrong-value false positives (e.g. "--audit-log-maxage
		// 90" registering as audit-log-maxage="true", then failing a
		// >=30 threshold check with a nonsensical "audit-log-maxage=true
		// is below 30" message on an actually-correctly-configured
		// cluster) rather than the documented "not parsed" silent-miss
		// this package's own doc comment claims. Found by an adversarial
		// audit, confirmed via a real scan.
		if i+1 < len(items) && !strings.HasPrefix(items[i+1], "--") {
			out[item] = append(out[item], items[i+1])
			i++
			continue
		}
		out[item] = append(out[item], "true")
	}
	return out
}

// check is one flag-based CIS control, evaluated against one component's
// parsed flags.
type check struct {
	ID                string
	Component         string
	CIS               string // CIS Kubernetes Benchmark v2.0.1 control ID
	Title             string
	Severity          findings.Severity
	Remediation       string
	VerificationSteps string
	// Eval reports whether the flags pass the check (ok) and, when they
	// don't, a sentence describing what was actually observed.
	Eval func(f flags) (ok bool, detail string)
}

func componentBinary(component string) string {
	switch component {
	case ComponentAPIServer:
		return "kube-apiserver"
	case ComponentControllerManager:
		return "kube-controller-manager"
	case ComponentScheduler:
		return "kube-scheduler"
	case ComponentEtcd:
		return "etcd"
	}
	return component
}

func (c check) evaluate(f flags, ref findings.ResourceRef, source string) (findings.Finding, bool) {
	ok, detail := c.Eval(f)
	if ok {
		return findings.Finding{}, false
	}
	msg := fmt.Sprintf(
		"[indirect signal — inferred from the %s static Pod's command-line flags via the Kubernetes API, not confirmed via node/file access] %s",
		componentBinary(c.Component), detail)
	return findings.Finding{
		ID:                findings.NewID(c.ID, ref),
		PolicyID:          c.ID,
		Title:             c.Title,
		Severity:          c.Severity,
		Category:          "control-plane-config",
		CIS:               []string{c.CIS},
		Resource:          ref,
		Message:           msg,
		Remediation:       c.Remediation,
		VerificationSteps: c.VerificationSteps,
		Source:            source,
	}, true
}

// Result is what Analyze found: findings from failed checks, plus which
// components were actually observed as Pods in this scan (so the caller can
// mark the corresponding compliance controls NOT_APPLICABLE for components
// that weren't, rather than reporting a false PASS).
type Result struct {
	Findings []findings.Finding
	Observed map[string]bool
}

// Analyze looks for control-plane static Pods among resources and evaluates
// every registered check against each one found. warn (nil is a valid
// no-op default, same as loader/engine's Warn callbacks) reports a Pod
// that was classified as a control-plane component but couldn't actually
// be checked — e.g. zero containers, which real cluster data essentially
// never produces but a hand-written/incomplete static manifest can.
func Analyze(resources []loader.Resource, source string, warn func(format string, args ...any)) (Result, error) {
	if warn == nil {
		warn = func(string, ...any) {}
	}
	res := Result{Observed: map[string]bool{}}
	var apiserverFlags flags

	for _, r := range resources {
		component, ok := classify(r)
		if !ok {
			continue
		}
		var pod corev1.Pod
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(r.Object.Object, &pod); err != nil {
			return Result{}, fmt.Errorf("converting Pod %s/%s: %w", r.Namespace(), r.Name(), err)
		}
		container, ok := mainContainer(pod, component)
		if !ok {
			warn("%s/%s was classified as %s but has no containers — skipping, nothing to check", r.Namespace(), r.Name(), component)
			continue
		}
		res.Observed[component] = true

		f := parseFlags(container.Command, container.Args)
		if component == ComponentAPIServer {
			apiserverFlags = f // captured for checkNamespacePSAEnforcement below
		}
		ref := findings.ResourceRef{
			APIVersion: "v1",
			Kind:       "Pod",
			Namespace:  r.Namespace(),
			Name:       r.Name(),
		}
		for _, c := range checks {
			if c.Component != component {
				continue
			}
			if finding, failed := c.evaluate(f, ref, r.Source); failed {
				res.Findings = append(res.Findings, finding)
			}
		}
	}

	res.Findings = append(res.Findings,
		checkNamespacePSAEnforcement(resources, apiserverFlags, res.Observed[ComponentAPIServer], source)...)

	return res, nil
}

// mainContainer picks the container that actually runs the component
// binary: these static pods are single-container by convention, but pick by
// name/command match if more than one container is present (e.g. a metrics
// or log-rotation sidecar).
func mainContainer(pod corev1.Pod, component string) (corev1.Container, bool) {
	if len(pod.Spec.Containers) == 0 {
		return corev1.Container{}, false
	}
	bin := componentBinary(component)
	for _, c := range pod.Spec.Containers {
		if strings.Contains(c.Name, bin) {
			return c, true
		}
		if len(c.Command) > 0 && strings.Contains(c.Command[0], bin) {
			return c, true
		}
	}
	return pod.Spec.Containers[0], true
}

// classify returns the control-plane component a Pod represents, and true
// if it's recognized as one. Detection prefers the standard kubeadm
// component/tier labels; it falls back to a name-prefix heuristic scoped to
// the kube-system namespace for distros that don't set them.
func classify(r loader.Resource) (string, bool) {
	gvk := r.GVK()
	if gvk.Group != "" || gvk.Kind != "Pod" {
		return "", false
	}
	if comp, ok := componentFromLabel(r.Object.GetLabels()["component"]); ok {
		return comp, true
	}
	if r.Namespace() != "kube-system" {
		return "", false
	}
	name := r.Name()
	switch {
	case strings.HasPrefix(name, "kube-apiserver"):
		return ComponentAPIServer, true
	case strings.HasPrefix(name, "kube-controller-manager"):
		return ComponentControllerManager, true
	case strings.HasPrefix(name, "kube-scheduler"):
		return ComponentScheduler, true
	case strings.HasPrefix(name, "etcd"):
		return ComponentEtcd, true
	}
	return "", false
}

func componentFromLabel(v string) (string, bool) {
	switch v {
	case "kube-apiserver":
		return ComponentAPIServer, true
	case "kube-controller-manager":
		return ComponentControllerManager, true
	case "kube-scheduler":
		return ComponentScheduler, true
	case "etcd":
		return ComponentEtcd, true
	}
	return "", false
}
