package engine_test

import (
	"strings"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/engine"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// TestControlPlanePolicyClassifiesByNamePrefixFallback guards a real
// coverage gap found by an adversarial audit: policies/controlplane/*.yaml
// checks used to rely solely on objectSelector: {component: kube-apiserver}
// (etc.), with no equivalent to internal/controlplane's Go-side name-prefix
// fallback for kube-system Pods on non-kubeadm distros that don't set the
// standard component label. That meant the same insecure Pod could be
// caught by the Go analyzer (controlplane-analyzer.*) but be completely
// invisible to the CEL checks (controlplane.*) — a silent split in
// coverage depending only on which mechanism produced a given check.
//
// Fixed by broadening matchConstraints to all Pods and moving the
// classification into each CEL expression itself (the same
// broad-match-narrow-condition pattern used throughout this codebase),
// mirroring internal/controlplane's classify(): match either the
// component label or a name-prefix in the kube-system namespace.
func TestControlPlanePolicyClassifiesByNamePrefixFallback(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	// No "component" label at all, but a kube-system Pod named like the
	// real static pod — the exact shape a non-kubeadm distro can produce.
	unlabeledButNamed := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver-node1
  namespace: kube-system
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --anonymous-auth=true
`)
	results := engine.EvaluateAll(policies, []loader.Resource{unlabeledButNamed}, engine.EvalOptions{})
	if len(findingsForPolicy(results, "controlplane.apiserver.anonymous-auth")) == 0 {
		t.Error("expected controlplane.apiserver.anonymous-auth to fire for an unlabeled but name-matched kube-system Pod")
	}

	// An ordinary, unrelated Pod (not in kube-system, no label, no
	// matching name) must never be classified as a control-plane
	// component.
	ordinary := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  namespace: default
spec:
  containers:
    - name: c
      image: nginx
`)
	results = engine.EvaluateAll(policies, []loader.Resource{ordinary}, engine.EvalOptions{})
	if len(findingsForPolicy(results, "controlplane.apiserver.anonymous-auth")) != 0 {
		t.Error("expected an ordinary Pod outside kube-system to never be classified as kube-apiserver")
	}

	// A Pod with SOME labels but no "component" key at all (a real shape
	// found on the live cluster this fix was verified against — e.g. a
	// CloudNativePG-managed Postgres Pod) must not error out: indexing a
	// map with a missing key is a CEL runtime error, not a false return,
	// so the guard must check key membership before indexing, not just
	// has(object.metadata.labels).
	labeledButNoComponentKey := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: unrelated-app-1
  namespace: default
  labels:
    app: unrelated-app
    cnpg.io/cluster: unrelated-app
spec:
  containers:
    - name: postgres
      image: postgres:16
`)
	var warnings []string
	results = engine.EvaluateAll(policies, []loader.Resource{labeledButNoComponentKey}, engine.EvalOptions{
		Warn: func(format string, args ...any) { warnings = append(warnings, format) },
	})
	for _, f := range results {
		if f.PolicyID == "controlplane.apiserver.anonymous-auth" {
			t.Errorf("expected no finding for a labeled Pod with no \"component\" key, got %+v", f)
		}
	}
	for _, w := range warnings {
		if strings.Contains(w, "controlplane.") {
			t.Errorf("expected no CEL evaluation error/warning for a labeled Pod with no \"component\" key (map indexing without a membership check errors, not returns false), got %q", w)
		}
	}

	// The original label-based path must still work unchanged.
	labeled := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: apiserver-abc123
  namespace: kube-system
  labels:
    component: kube-apiserver
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --anonymous-auth=true
`)
	results = engine.EvaluateAll(policies, []loader.Resource{labeled}, engine.EvalOptions{})
	if len(findingsForPolicy(results, "controlplane.apiserver.anonymous-auth")) == 0 {
		t.Error("expected controlplane.apiserver.anonymous-auth to still fire via the component label path")
	}
}
