package engine_test

// These tests exist because matchConstraints.apiVersions is "*" for the
// Capsule/Istio policies below: that guarantees the object gets matched
// regardless of version, but says nothing about whether the CEL's field
// paths still resolve correctly against an OLDER version's actual shape.
// A renamed/missing field wouldn't error — CEL's `has(...)` just returns
// false, which these policies' "pass" branch treats as compliant. Verified
// against the real upstream source (istio/api, projectcapsule/capsule) that
// this is safe; these fixtures pin that verification down as a regression
// test instead of leaving it as an unverifiable claim in a comment.

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/engine"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// capsuleTenantV1beta1Hardened is shaped like a Capsule v1beta1 Tenant
// (apiVersion capsule.clastix.io/v1beta1) with every field the network
// policy/resource quota/limit range/cluster-admin checks depend on set
// correctly. It deliberately has no spec.namespaceOptions.requiredMetadata
// — that field doesn't exist in v1beta1 at all (introduced in v1beta2) — so
// multitenancy.capsule-tenant-no-psa-enforcement is expected to still fire
// here; see docs/compliance.md's Capsule section for why that's correct,
// not a bug.
const capsuleTenantV1beta1Hardened = `
apiVersion: capsule.clastix.io/v1beta1
kind: Tenant
metadata:
  name: hardened-v1beta1
spec:
  owners:
    - name: bob
      kind: User
  networkPolicies:
    items:
      - podSelector: {}
  resourceQuotas:
    items:
      - hard:
          limits.cpu: "10"
  limitRanges:
    items:
      - limits:
          - type: Container
  additionalRoleBindings:
    - clusterRoleName: tenant-viewer
      subjects:
        - kind: User
          name: bob
`

func TestCapsuleV1beta1_FieldsPresentInBothVersionsPass(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	results := engine.EvaluateAll(policies, []loader.Resource{mustResource(t, capsuleTenantV1beta1Hardened)}, engine.EvalOptions{})

	for _, id := range []string{
		"multitenancy.capsule-tenant-no-network-policies",
		"multitenancy.capsule-tenant-no-resource-quota",
		"multitenancy.capsule-tenant-no-limit-range",
		"multitenancy.capsule-tenant-cluster-admin-binding",
	} {
		if got := findingsForPolicy(results, id); len(got) != 0 {
			t.Errorf("%s: expected no finding on a hardened v1beta1 Tenant (field exists identically in v1beta1), got %+v", id, got)
		}
	}
}

func TestCapsuleV1beta1_PSAEnforcementAlwaysFires(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	results := engine.EvaluateAll(policies, []loader.Resource{mustResource(t, capsuleTenantV1beta1Hardened)}, engine.EvalOptions{})

	if got := findingsForPolicy(results, "multitenancy.capsule-tenant-no-psa-enforcement"); len(got) == 0 {
		t.Error("expected capsule-tenant-no-psa-enforcement to still fire on a v1beta1 Tenant — requiredMetadata genuinely doesn't exist pre-v1beta2, this is a true positive, not a gap in this test")
	}
}

// istioV1beta1PermissiveMTLS and istioV1beta1WideOpenAuthzPolicy use the
// older security.istio.io/v1beta1 apiVersion directly. Verified upstream
// that v1's PeerAuthentication/AuthorizationPolicy are literal Go type
// aliases of v1beta1's (istio/api's security/v1/*_alias.gen.go) — so these
// should behave identically to the v1 fixtures used elsewhere in this
// package, not just compile without erroring.
const istioV1beta1PermissiveMTLS = `
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: payments
spec:
  mtls:
    mode: PERMISSIVE
`

const istioV1beta1WideOpenAuthzPolicy = `
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: wide-open
  namespace: payments
spec:
  action: ALLOW
  rules:
    - to:
        - operation:
            paths: ["*"]
`

func TestIstioV1beta1_PoliciesFireIdenticallyToV1(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	resources := []loader.Resource{
		mustResource(t, istioV1beta1PermissiveMTLS),
		mustResource(t, istioV1beta1WideOpenAuthzPolicy),
	}
	results := engine.EvaluateAll(policies, resources, engine.EvalOptions{})

	for _, id := range []string{
		"istio.peer-authentication-permissive-mtls",
		"istio.authorization-policy-no-source-restriction",
		"istio.authorization-policy-wildcard-path",
	} {
		if got := findingsForPolicy(results, id); len(got) == 0 {
			t.Errorf("%s: expected a finding on a security.istio.io/v1beta1 object (should behave identically to v1 — they're the same Go type)", id)
		}
	}
}
