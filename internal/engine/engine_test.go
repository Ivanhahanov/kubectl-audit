package engine_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/ivanhahanov/kubectl-audit/internal/engine"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

func mustResource(t *testing.T, doc string) loader.Resource {
	t.Helper()
	var m map[string]interface{}
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	return loader.Resource{Object: &unstructured.Unstructured{Object: m}, Source: "test"}
}

func findingsForPolicy(list []findings.Finding, policyID string) []findings.Finding {
	var out []findings.Finding
	for _, f := range list {
		if f.PolicyID == policyID {
			out = append(out, f)
		}
	}
	return out
}

const badPod = `
apiVersion: v1
kind: Pod
metadata:
  name: bad
  namespace: default
spec:
  containers:
    - name: c
      image: nginx:latest
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
`

const hardenedPod = `
apiVersion: v1
kind: Pod
metadata:
  name: good
  namespace: good-app
spec:
  serviceAccountName: good-sa
  containers:
    - name: c
      image: nginx:1.25.3
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
        seccompProfile:
          type: RuntimeDefault
      resources:
        limits:
          cpu: "100m"
          memory: "128Mi"
`

// TestSeccompCheckCatchesContainerLevelOverride guards a real false
// negative found by an adversarial audit: a secure pod-level
// seccompProfile: RuntimeDefault previously masked an explicit,
// more-dangerous container-level "Unconfined" override, because the old
// expression was (pod-ok) || (all-containers-ok) — the first disjunct
// short-circuited true regardless of what an individual container set.
// Cross-confirmed against the real k8s.io/pod-security-admission library
// (internal/pss), which correctly caught this same case.
func TestSeccompCheckCatchesContainerLevelOverride(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	overridden := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: p
  namespace: default
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: c
      image: nginx:1.25.3
      securityContext:
        seccompProfile:
          type: Unconfined
`)
	results := engine.EvaluateAll(policies, []loader.Resource{overridden}, engine.EvalOptions{})
	if len(findingsForPolicy(results, "workload.seccomp-profile-required")) == 0 {
		t.Error("expected workload.seccomp-profile-required to fire when a container explicitly overrides a secure pod-level seccompProfile with Unconfined")
	}

	// Inheritance (no container-level override at all) must still pass —
	// this is the case the check exists to recognize as safe.
	inherited := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: p
  namespace: default
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: c
      image: nginx:1.25.3
`)
	inheritedResults := engine.EvaluateAll(policies, []loader.Resource{inherited}, engine.EvalOptions{})
	if len(findingsForPolicy(inheritedResults, "workload.seccomp-profile-required")) != 0 {
		t.Error("expected no finding when a container correctly inherits a secure pod-level seccompProfile")
	}
}

// TestRunAsNonRootCheckCatchesContainerLevelOverride guards the same bug
// shape, found in the same audit, in workload.run-as-non-root: a secure
// pod-level runAsNonRoot: true previously masked an explicit
// container-level runAsNonRoot: false (an explicit grant of root back).
func TestRunAsNonRootCheckCatchesContainerLevelOverride(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	overridden := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: p
  namespace: default
spec:
  securityContext:
    runAsNonRoot: true
  containers:
    - name: c
      image: nginx:1.25.3
      securityContext:
        runAsNonRoot: false
        runAsUser: 0
`)
	results := engine.EvaluateAll(policies, []loader.Resource{overridden}, engine.EvalOptions{})
	if len(findingsForPolicy(results, "workload.run-as-non-root")) == 0 {
		t.Error("expected workload.run-as-non-root to fire when a container explicitly overrides a secure pod-level runAsNonRoot with false")
	}

	inherited := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: p
  namespace: default
spec:
  securityContext:
    runAsNonRoot: true
  containers:
    - name: c
      image: nginx:1.25.3
`)
	inheritedResults := engine.EvaluateAll(policies, []loader.Resource{inherited}, engine.EvalOptions{})
	if len(findingsForPolicy(inheritedResults, "workload.run-as-non-root")) != 0 {
		t.Error("expected no finding when a container correctly inherits a secure pod-level runAsNonRoot")
	}
}

func TestKnownWeakPlaceholderSecretValueDetected(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	weak := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app-credentials
  namespace: default
data:
  password: cGFzc3dvcmQ=
`)
	strong := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app-credentials
  namespace: default
data:
  password: WjlrTHFSNXZUOFBtSDNuWHlBMmNFN2dCNGZOUXJXbUs=
`)
	tlsTyped := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app-tls
  namespace: default
type: kubernetes.io/tls
data:
  tls.crt: cGFzc3dvcmQ=
  tls.key: cGFzc3dvcmQ=
`)

	bad := engine.EvaluateAll(policies, []loader.Resource{weak}, engine.EvalOptions{})
	if len(findingsForPolicy(bad, "secrets.known-weak-placeholder-value")) == 0 {
		t.Errorf("expected secrets.known-weak-placeholder-value to fire on a Secret whose value is literally \"password\"")
	}

	good := engine.EvaluateAll(policies, []loader.Resource{strong}, engine.EvalOptions{})
	if len(findingsForPolicy(good, "secrets.known-weak-placeholder-value")) != 0 {
		t.Errorf("expected no finding on a Secret with a real random-looking value")
	}

	typedSecret := engine.EvaluateAll(policies, []loader.Resource{tlsTyped}, engine.EvalOptions{})
	if len(findingsForPolicy(typedSecret, "secrets.known-weak-placeholder-value")) != 0 {
		t.Errorf("expected no finding on a kubernetes.io/tls-typed Secret even though its data values happen to match the weak-value list — type: Opaque is required")
	}

	stringDataWeak := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app-credentials
  namespace: default
stringData:
  password: password
`)
	stringDataResult := engine.EvaluateAll(policies, []loader.Resource{stringDataWeak}, engine.EvalOptions{})
	if len(findingsForPolicy(stringDataResult, "secrets.known-weak-placeholder-value")) == 0 {
		t.Errorf("expected secrets.known-weak-placeholder-value to fire on a stringData-authored Secret whose value is literally \"password\"")
	}

	basicAuthWeak := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app-basic-auth
  namespace: default
type: kubernetes.io/basic-auth
data:
  username: YWRtaW4=
  password: cGFzc3dvcmQ=
`)
	basicAuthResult := engine.EvaluateAll(policies, []loader.Resource{basicAuthWeak}, engine.EvalOptions{})
	if len(findingsForPolicy(basicAuthResult, "secrets.known-weak-placeholder-value")) == 0 {
		t.Errorf("expected secrets.known-weak-placeholder-value to fire on a kubernetes.io/basic-auth Secret's weak password field")
	}
}

func TestBuiltinPoliciesLoadAndCompile(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	if len(policies) != 126 {
		t.Fatalf("expected 126 built-in policies, got %d", len(policies))
	}
}

func TestPrivilegedContainerDetected(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	bad := engine.EvaluateAll(policies, []loader.Resource{mustResource(t, badPod)}, engine.EvalOptions{})
	if len(findingsForPolicy(bad, "workload.no-privileged-containers")) != 2 {
		t.Fatalf("expected 2 distinct findings from workload.no-privileged-containers (privileged + allowPrivilegeEscalation), got %d: %+v",
			len(findingsForPolicy(bad, "workload.no-privileged-containers")), bad)
	}

	good := engine.EvaluateAll(policies, []loader.Resource{mustResource(t, hardenedPod)}, engine.EvalOptions{})
	for _, f := range good {
		t.Errorf("unexpected finding on fully-hardened pod: %s: %s", f.PolicyID, f.Message)
	}
}

func TestDeploymentPodTemplateShapeIsChecked(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	deployment := mustResource(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-deploy
  namespace: default
spec:
  selector:
    matchLabels:
      app: bad
  template:
    metadata:
      labels:
        app: bad
    spec:
      containers:
        - name: c
          image: nginx:latest
          securityContext:
            privileged: true
`)

	results := engine.EvaluateAll(policies, []loader.Resource{deployment}, engine.EvalOptions{})
	if len(findingsForPolicy(results, "workload.no-privileged-containers")) == 0 {
		t.Errorf("expected workload.no-privileged-containers to catch a privileged container nested under spec.template.spec")
	}
	if len(findingsForPolicy(results, "workload.no-latest-tag")) == 0 {
		t.Errorf("expected workload.no-latest-tag to catch an implicit :latest tag under spec.template.spec")
	}
}

func TestNoLatestTagImagePinning(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	cases := []struct {
		image string
		want  bool // true = expect a finding
	}{
		{"nginx", true},
		{"nginx:latest", true},
		{"nginx:1.25.3", false},
		{"myregistry.io:5000/nginx", true},
		{"myregistry.io:5000/nginx:1.25.3", false},
		{"nginx@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678", false},
	}

	for _, c := range cases {
		pod := mustResource(t, `
apiVersion: v1
kind: Pod
metadata:
  name: p
  namespace: default
spec:
  containers:
    - name: c
      image: `+c.image+`
`)
		results := engine.EvaluateAll(policies, []loader.Resource{pod}, engine.EvalOptions{})
		got := len(findingsForPolicy(results, "workload.no-latest-tag")) > 0
		if got != c.want {
			t.Errorf("image %q: expected finding=%v, got %v", c.image, c.want, got)
		}
	}
}

func TestRBACWildcardAndClusterAdminPolicies(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	wildcardRole := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: too-broad
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
`)
	adminBinding := mustResource(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: User
    name: alice
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
  name: view
subjects:
  - kind: Group
    name: system:unauthenticated
    apiGroup: rbac.authorization.k8s.io
`)

	results := engine.EvaluateAll(policies, []loader.Resource{wildcardRole, adminBinding, anonBinding}, engine.EvalOptions{})

	if len(findingsForPolicy(results, "rbac.no-wildcard-rules")) == 0 {
		t.Errorf("expected rbac.no-wildcard-rules to fire on the wildcard ClusterRole")
	}
	if len(findingsForPolicy(results, "rbac.no-cluster-admin-binding")) == 0 {
		t.Errorf("expected rbac.no-cluster-admin-binding to fire on the cluster-admin binding")
	}
	if len(findingsForPolicy(results, "rbac.no-anonymous-binding")) == 0 {
		t.Errorf("expected rbac.no-anonymous-binding to fire on the system:unauthenticated binding")
	}
}

func TestSpecVariablesRejected(t *testing.T) {
	docs, err := engine.ParsePolicyDocs("inline", []byte(`
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: uses-variables
spec:
  variables:
    - name: foo
      expression: "1 + 1"
  validations:
    - expression: "variables.foo == 2"
`))
	if err != nil {
		t.Fatalf("ParsePolicyDocs: %v", err)
	}
	meta := engine.ExtractMeta(docs[0])
	if _, err := engine.Compile(docs[0], meta); err == nil {
		t.Errorf("expected Compile to reject a policy using spec.variables")
	}
}

func TestAuthorizerVariableRejected(t *testing.T) {
	docs, err := engine.ParsePolicyDocs("inline", []byte(`
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: uses-authorizer
spec:
  validations:
    - expression: "authorizer.group('').resource('pods').check('list').allowed()"
`))
	if err != nil {
		t.Fatalf("ParsePolicyDocs: %v", err)
	}
	meta := engine.ExtractMeta(docs[0])
	if _, err := engine.Compile(docs[0], meta); err == nil {
		t.Errorf("expected Compile to reject a policy referencing the undeclared 'authorizer' variable")
	}
}

func TestIngressTLSRequired(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	noTLS := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: plain
  namespace: default
spec:
  rules:
    - host: example.com
`)
	withTLS := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure
  namespace: default
spec:
  tls:
    - hosts: ["example.com"]
      secretName: example-tls
  rules:
    - host: example.com
`)

	bad := engine.EvaluateAll(policies, []loader.Resource{noTLS}, engine.EvalOptions{})
	if len(findingsForPolicy(bad, "network.ingress-tls-required")) == 0 {
		t.Errorf("expected network.ingress-tls-required to fire on an Ingress with no spec.tls")
	}

	good := engine.EvaluateAll(policies, []loader.Resource{withTLS}, engine.EvalOptions{})
	if len(findingsForPolicy(good, "network.ingress-tls-required")) != 0 {
		t.Errorf("expected no finding on an Ingress with spec.tls set")
	}
}

// TestIngressTLSRequired_MatchesOldAPIVersionsToo guards against the
// version-skew bug class this policy used to have: matchConstraints was
// pinned to networking.k8s.io/v1 only, so an Ingress loaded from an old
// manifest (extensions/v1beta1, still parseable by this tool's static-file
// mode even though Kubernetes itself removed it in 1.22) silently never
// matched — not an error, just zero findings. spec.tls has been
// byte-identical since Ingress's earliest v1beta1 shape, so there's no
// reason this check should be version-pinned at all.
func TestIngressTLSRequired_MatchesOldAPIVersionsToo(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	old := mustResource(t, `
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: old-plain
  namespace: default
spec:
  rules:
    - host: example.com
`)
	results := engine.EvaluateAll(policies, []loader.Resource{old}, engine.EvalOptions{})
	if len(findingsForPolicy(results, "network.ingress-tls-required")) == 0 {
		t.Error("expected network.ingress-tls-required to fire on an extensions/v1beta1 Ingress with no spec.tls, not just networking.k8s.io/v1")
	}
}

func TestDeprecatedIngressAPIVersion(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	old := mustResource(t, `
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: legacy
  namespace: default
spec:
  rules:
    - host: example.com
`)
	current := mustResource(t, `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: current
  namespace: default
spec:
  tls:
    - hosts: ["example.com"]
      secretName: example-tls
  rules:
    - host: example.com
`)

	badResults := engine.EvaluateAll(policies, []loader.Resource{old}, engine.EvalOptions{})
	if len(findingsForPolicy(badResults, "network.no-deprecated-ingress-api-version")) == 0 {
		t.Errorf("expected network.no-deprecated-ingress-api-version to fire on extensions/v1beta1 Ingress")
	}

	goodResults := engine.EvaluateAll(policies, []loader.Resource{current}, engine.EvalOptions{})
	if len(findingsForPolicy(goodResults, "network.no-deprecated-ingress-api-version")) != 0 {
		t.Errorf("expected no finding on a networking.k8s.io/v1 Ingress")
	}
}
