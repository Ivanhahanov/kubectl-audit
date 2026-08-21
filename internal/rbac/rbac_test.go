package rbac_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/rbac"
)

func mustResource(t *testing.T, doc string) loader.Resource {
	t.Helper()
	var m map[string]interface{}
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	return loader.Resource{Object: &unstructured.Unstructured{Object: m}, Source: "test"}
}

func hasPolicy(list []findings.Finding, policyID string) bool {
	for _, f := range list {
		if f.PolicyID == policyID {
			return true
		}
	}
	return false
}

func TestEscalationVerbDetected(t *testing.T) {
	role := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: escalator
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["escalate"]
`)
	binding := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: escalator-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: escalator
subjects:
  - kind: User
    name: alice
    apiGroup: rbac.authorization.k8s.io
`)

	result, err := rbac.Analyze([]loader.Resource{role, binding}, "test", false)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !hasPolicy(result.Findings, "rbac-analyzer.escalation-verb") {
		t.Errorf("expected an rbac-analyzer.escalation-verb finding, got %+v", result.Findings)
	}
}

// TestEscalationVerbDetectedViaWildcard guards a real false negative found
// by an adversarial audit: checkEscalationVerbs only matched the literal
// strings "escalate"/"bind"/"impersonate" — a role scoped to just
// clusterroles/clusterrolebindings with verbs: ["*"] (which obviously
// grants escalate/bind too) produced zero findings, even though the
// sibling checks in the same file (checkExecAccess, checkSecretsBreadth,
// checkRBACSelfModification) all already handled the wildcard-verb case
// correctly. rbac.no-wildcard-rules' CEL check doesn't catch this either —
// it fires on a full apiGroups+resources+verbs wildcard, not a
// resource-scoped one like this.
func TestEscalationVerbDetectedViaWildcard(t *testing.T) {
	role := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: escalator
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles", "clusterrolebindings"]
    verbs: ["*"]
`)
	binding := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: escalator-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: escalator
subjects:
  - kind: User
    name: mallory
    apiGroup: rbac.authorization.k8s.io
`)

	result, err := rbac.Analyze([]loader.Resource{role, binding}, "test", false)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !hasPolicy(result.Findings, "rbac-analyzer.escalation-verb") {
		t.Errorf("expected an rbac-analyzer.escalation-verb finding for a role with verbs: [\"*\"] on clusterroles/clusterrolebindings, got %+v", result.Findings)
	}
}

func TestPodExecAccessDetected(t *testing.T) {
	role := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: exec-role
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
`)
	binding := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: exec-binding
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: exec-role
subjects:
  - kind: User
    name: bob
    apiGroup: rbac.authorization.k8s.io
`)

	result, err := rbac.Analyze([]loader.Resource{role, binding}, "test", false)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !hasPolicy(result.Findings, "rbac-analyzer.pod-exec-access") {
		t.Errorf("expected an rbac-analyzer.pod-exec-access finding, got %+v", result.Findings)
	}
}

func TestClusterAdminIsSyntheticallyResolved(t *testing.T) {
	// The cluster-admin ClusterRole is built into every real cluster and is
	// never present in static manifests. The analyzer must still resolve it
	// so bindings to it aren't silently treated as granting zero access.
	binding := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
`)
	sa := mustResource(t, `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: default
`)

	result, err := rbac.Analyze([]loader.Resource{binding, sa}, "test", false)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !hasPolicy(result.Findings, "rbac-analyzer.default-serviceaccount-bound") {
		t.Errorf("expected default-serviceaccount-bound finding when the default SA is bound to (synthetic) cluster-admin, got %+v", result.Findings)
	}
	if !hasPolicy(result.Findings, "rbac-analyzer.automount-with-sensitive-access") {
		t.Errorf("expected automount-with-sensitive-access finding for the default SA, got %+v", result.Findings)
	}

	var found bool
	for _, m := range result.Model {
		if m.Subject.Kind == "ServiceAccount" && m.Subject.Name == "default" {
			found = true
			if len(m.Permissions) == 0 {
				t.Errorf("expected the default SA's role model to list cluster-admin's resolved permissions, got none")
			}
		}
	}
	if !found {
		t.Fatalf("expected a role-model entry for the default ServiceAccount")
	}
}

func TestNoFindingsForMinimalRole(t *testing.T) {
	role := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: reader
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
`)
	binding := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: reader-binding
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: reader
subjects:
  - kind: User
    name: carol
    apiGroup: rbac.authorization.k8s.io
`)

	result, err := rbac.Analyze([]loader.Resource{role, binding}, "test", false)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range result.Findings {
		t.Errorf("unexpected finding for a minimal read-only role: %s: %s", f.PolicyID, f.Message)
	}
}

func TestAggregatedClusterRoleResolvedInStaticMode(t *testing.T) {
	// Mirrors how the built-in admin/edit/view roles work: an aggregating
	// ClusterRole with no rules of its own, and a contributed ClusterRole
	// carrying the actual (dangerous) rule plus the label the selector
	// matches on. In a real cluster the aggregating role's .rules would
	// already be materialized by the API server; here it's raw static YAML,
	// so the analyzer must resolve it itself.
	aggregating := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: custom-admin
aggregationRule:
  clusterRoleSelectors:
    - matchLabels:
        rbac.example.com/aggregate-to-custom-admin: "true"
rules: []
`)
	contributed := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: custom-admin-secrets
  labels:
    rbac.example.com/aggregate-to-custom-admin: "true"
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
`)
	binding := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: custom-admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: custom-admin
subjects:
  - kind: User
    name: dave
    apiGroup: rbac.authorization.k8s.io
`)

	result, err := rbac.Analyze([]loader.Resource{aggregating, contributed, binding}, "test", false)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !hasPolicy(result.Findings, "rbac-analyzer.broad-secrets-access") {
		t.Errorf("expected the aggregated secrets rule to be resolved and flagged as cluster-wide secrets access, got %+v", result.Findings)
	}
}

func TestLiveClusterAggregatedRoleNotOverwritten(t *testing.T) {
	// If .rules is already populated (as a real API server would return),
	// the resolver must leave it alone rather than re-deriving it.
	aggregating := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: already-materialized
aggregationRule:
  clusterRoleSelectors:
    - matchLabels:
        rbac.example.com/aggregate-to-already-materialized: "true"
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
`)
	contributed := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: contributor
  labels:
    rbac.example.com/aggregate-to-already-materialized: "true"
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
`)
	binding := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: already-materialized
subjects:
  - kind: User
    name: erin
    apiGroup: rbac.authorization.k8s.io
`)

	result, err := rbac.Analyze([]loader.Resource{aggregating, contributed, binding}, "test", false)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if hasPolicy(result.Findings, "rbac-analyzer.broad-secrets-access") {
		t.Errorf("did not expect the already-materialized role's .rules to be overwritten with the contributor's secrets rule, got %+v", result.Findings)
	}
}

func hasSubject(model []rbac.SubjectModel, kind, name string) bool {
	for _, m := range model {
		if m.Subject.Kind == kind && m.Subject.Name == name {
			return true
		}
	}
	return false
}

// TestBuiltinSystemSubjectsFilteredByDefault covers the kubeadm/kind
// bootstrap case: the cluster-admin ClusterRoleBinding to the system:masters
// group is how every self-hosted cluster satisfies "some identity must have
// full access to bootstrap RBAC" — not a remediable misconfiguration — so it
// (and other system:-prefixed groups/users) shouldn't generate
// least-privilege findings or role-model rows by default. system:anonymous
// is the deliberate exception: granting it anything is exactly what should
// still be caught.
func TestBuiltinSystemSubjectsFilteredByDefault(t *testing.T) {
	role := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-admin
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
`)
	mastersBinding := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: Group
    name: system:masters
    apiGroup: rbac.authorization.k8s.io
`)
	anonBinding := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: anon-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: Group
    name: system:anonymous
    apiGroup: rbac.authorization.k8s.io
`)
	resources := []loader.Resource{role, mastersBinding, anonBinding}

	filtered, err := rbac.Analyze(resources, "test", false)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if hasSubject(filtered.Model, "Group", "system:masters") {
		t.Error("expected system:masters to be filtered out of the role model by default")
	}
	for _, f := range filtered.Findings {
		if f.Resource.Name == "system:masters" && f.PolicyID != "rbac-analyzer.system-masters-usage" {
			t.Errorf("expected no *generic* least-privilege findings for system:masters by default, got %+v", f)
		}
	}
	if !hasPolicy(filtered.Findings, "rbac-analyzer.system-masters-usage") {
		t.Error("expected the dedicated system-masters-usage tracking finding to still fire even by default")
	}
	if !hasSubject(filtered.Model, "Group", "system:anonymous") {
		t.Error("expected system:anonymous to remain visible even by default")
	}

	full, err := rbac.Analyze(resources, "test", true)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !hasSubject(full.Model, "Group", "system:masters") {
		t.Error("expected system:masters to be visible with includeSystemSubjects=true")
	}
}
