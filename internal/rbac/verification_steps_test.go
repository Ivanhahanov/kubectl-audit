package rbac_test

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/rbac"
)

// TestEveryCheckHasVerificationSteps guards the triage-tool content
// requirement (see docs/triage.md): every native rbac-analyzer.* check must
// produce findings with a non-empty VerificationSteps. Builds one fixture
// set that triggers all seven known check IDs at once, so a newly added
// check that forgets VerificationSteps — or an existing one whose steps
// text regresses to empty — fails loudly here instead of silently shipping
// with no triage guidance.
func TestEveryCheckHasVerificationSteps(t *testing.T) {
	resources := []loader.Resource{
		// escalation-verb
		mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: escalator
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["escalate"]
`),
		mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: escalator-binding
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: escalator}
subjects:
  - {kind: User, name: alice, apiGroup: rbac.authorization.k8s.io}
`),
		// pod-exec-access
		mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: exec-role
rules:
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
`),
		mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: exec-binding
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: exec-role}
subjects:
  - {kind: User, name: bob, apiGroup: rbac.authorization.k8s.io}
`),
		// broad-secrets-access (cluster-wide via ClusterRoleBinding)
		mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secrets-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
`),
		mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: secrets-reader-binding
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: secrets-reader}
subjects:
  - {kind: User, name: carol, apiGroup: rbac.authorization.k8s.io}
`),
		// rbac-self-modification
		mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: rbac-writer
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles", "clusterrolebindings"]
    verbs: ["create", "update"]
`),
		mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: rbac-writer-binding
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: rbac-writer}
subjects:
  - {kind: User, name: dave, apiGroup: rbac.authorization.k8s.io}
`),
		// default-serviceaccount-bound
		mustResource(t, `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: has-default-sa-role
`),
		mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: some-role
  namespace: has-default-sa-role
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
`),
		mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: default-sa-binding
  namespace: has-default-sa-role
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: some-role}
subjects:
  - {kind: ServiceAccount, name: default, namespace: has-default-sa-role}
`),
		// automount-with-sensitive-access
		mustResource(t, `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: automount-sa
  namespace: automount-ns
`),
		mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: automount-role
  namespace: automount-ns
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
`),
		mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: automount-binding
  namespace: automount-ns
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: automount-role}
subjects:
  - {kind: ServiceAccount, name: automount-sa, namespace: automount-ns}
`),
		// system-masters-usage
		mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: masters-binding
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects:
  - {kind: Group, name: system:masters, apiGroup: rbac.authorization.k8s.io}
`),
	}

	result, err := rbac.Analyze(resources, "test", false)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	want := map[string]bool{
		"rbac-analyzer.escalation-verb":                 false,
		"rbac-analyzer.pod-exec-access":                 false,
		"rbac-analyzer.broad-secrets-access":            false,
		"rbac-analyzer.rbac-self-modification":          false,
		"rbac-analyzer.default-serviceaccount-bound":    false,
		"rbac-analyzer.automount-with-sensitive-access": false,
		"rbac-analyzer.system-masters-usage":            false,
	}
	for _, f := range result.Findings {
		if _, known := want[f.PolicyID]; known {
			want[f.PolicyID] = true
		}
		if f.VerificationSteps == "" {
			t.Errorf("finding %s (%s) has no VerificationSteps", f.PolicyID, f.Resource.String())
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("expected a %s finding from this fixture set — test fixture may be broken, or the check itself may be", id)
		}
	}
}
