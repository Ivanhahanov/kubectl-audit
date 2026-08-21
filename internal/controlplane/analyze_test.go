package controlplane

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

func apiserverPod(name string, extraArgs ...string) loader.Resource {
	command := []string{
		"kube-apiserver",
		"--advertise-address=10.0.0.1",
		"--anonymous-auth=false",
		"--authorization-mode=Node,RBAC",
		"--profiling=false",
		"--audit-log-path=/var/log/kubernetes/audit.log",
		"--audit-log-maxage=30",
		"--audit-log-maxbackup=10",
		"--audit-log-maxsize=100",
		"--etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt",
		"--etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key",
		"--tls-cert-file=/etc/kubernetes/pki/apiserver.crt",
		"--tls-private-key-file=/etc/kubernetes/pki/apiserver.key",
		"--client-ca-file=/etc/kubernetes/pki/ca.crt",
		"--etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt",
		"--kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt",
		"--kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key",
		"--kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt",
		"--service-account-key-file=/etc/kubernetes/pki/sa.pub",
		"--encryption-provider-config=/etc/kubernetes/enc/config.yaml",
		"--audit-policy-file=/etc/kubernetes/policies/audit-policy.yaml",
		"--service-account-extend-token-expiration=false",
	}
	command = append(command, extraArgs...)

	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      name,
			"namespace": "kube-system",
			"labels":    map[string]any{"component": "kube-apiserver", "tier": "control-plane"},
		},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{
					"name":    "kube-apiserver",
					"command": toAnySlice(command),
				},
			},
		},
	}}
	return loader.Resource{Object: obj, Source: "cluster:test"}
}

func toAnySlice(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func TestParseFlags(t *testing.T) {
	f := parseFlags([]string{"kube-apiserver", "--anonymous-auth=false", "--enable-admission-plugins=NodeRestriction,ServiceAccount", "--audit-log-maxage=30"}, nil)
	if !f.equals("anonymous-auth", "false") {
		t.Errorf("expected anonymous-auth=false, got %v", f["anonymous-auth"])
	}
	if !f.csvContains("enable-admission-plugins", "NodeRestriction") {
		t.Errorf("expected enable-admission-plugins to contain NodeRestriction, got %v", f["enable-admission-plugins"])
	}
	if f.isSet("does-not-exist") {
		t.Error("expected does-not-exist to be unset")
	}
	if !f.atLeast("audit-log-maxage", 10) {
		t.Error("audit-log-maxage not parsed")
	}
}

// TestParseFlags_SpaceSeparatedForm guards a real bug found by an
// adversarial audit: "--flag value" as two consecutive args-list elements
// (a real, valid container-arg style some non-kubeadm distros use)
// previously registered as flag="true" (an ambiguous boolean marker)
// instead of capturing "value" — producing an ACTIVE, wrong-value false
// positive on a correctly-configured flag (e.g. "--audit-log-maxage 90"
// failing a >=30 threshold check because it compared "true" instead of
// "90"), not just the documented "silently not parsed" miss.
func TestParseFlags_SpaceSeparatedForm(t *testing.T) {
	f := parseFlags([]string{"kube-apiserver", "--audit-log-maxage", "90", "--anonymous-auth", "false", "--profiling"}, nil)
	if !f.atLeast("audit-log-maxage", 30) {
		t.Errorf("expected audit-log-maxage (space-separated form) to parse as 90, got %v", f["audit-log-maxage"])
	}
	if !f.equals("anonymous-auth", "false") {
		t.Errorf("expected anonymous-auth (space-separated form) to parse as \"false\", got %v", f["anonymous-auth"])
	}
	// A genuine bare boolean flag (no following value at all, or followed
	// by another flag) must still default to "true" — this is real and
	// common for actual boolean apiserver flags passed with no "=value".
	if !f.equals("profiling", "true") {
		t.Errorf("expected a trailing bare flag with nothing after it to still default to \"true\", got %v", f["profiling"])
	}
}

func TestClassify(t *testing.T) {
	r := apiserverPod("kube-apiserver-node1")
	comp, ok := classify(r)
	if !ok || comp != ComponentAPIServer {
		t.Fatalf("expected apiserver, got %q, %v", comp, ok)
	}

	other := loader.Resource{Object: &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "my-app", "namespace": "default"},
	}}}
	if _, ok := classify(other); ok {
		t.Error("expected an ordinary Pod in a user namespace not to classify as a control-plane component")
	}
}

func TestAnalyzeHealthyAPIServerPasses(t *testing.T) {
	res, err := Analyze([]loader.Resource{apiserverPod("kube-apiserver-node1")}, "cluster:test", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !res.Observed[ComponentAPIServer] {
		t.Fatal("expected apiserver to be observed")
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected a fully-hardened apiserver to produce no findings, got %+v", res.Findings)
	}
}

func TestAnalyzeFlagsAllowAllFails(t *testing.T) {
	res, err := Analyze([]loader.Resource{apiserverPod("kube-apiserver-node1",
		"--authorization-mode=AlwaysAllow",
		"--enable-admission-plugins=AlwaysAdmit",
		"--audit-log-maxage=1",
	)}, "cluster:test", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	byID := map[string]bool{}
	for _, f := range res.Findings {
		byID[f.PolicyID] = true
	}
	if !byID["controlplane-analyzer.apiserver.authz-always-allow"] {
		t.Error("expected an authz-always-allow finding")
	}
	if !byID["controlplane-analyzer.apiserver.always-admit"] {
		t.Error("expected an always-admit finding")
	}
	if !byID["controlplane-analyzer.apiserver.audit-log-maxage"] {
		t.Error("expected an audit-log-maxage finding")
	}
	// --enable-admission-plugins=AlwaysAdmit is an explicit list that omits
	// ServiceAccount/NamespaceLifecycle/NodeRestriction, so those should also fail.
	if !byID["controlplane-analyzer.apiserver.admission-serviceaccount"] {
		t.Error("expected an admission-serviceaccount finding (explicit enable-list omits it)")
	}
	for _, f := range res.Findings {
		if f.PolicyID == "controlplane-analyzer.apiserver.authz-always-allow" && !strings.Contains(f.Message, "[indirect signal") {
			t.Errorf("expected finding message to be marked as an indirect signal, got %q", f.Message)
		}
	}
}

func TestAnalyzeNoControlPlanePodsObservesNothing(t *testing.T) {
	res, err := Analyze(nil, "cluster:test", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.Observed) != 0 {
		t.Errorf("expected no components observed, got %v", res.Observed)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings when no control-plane pods are present, got %+v", res.Findings)
	}
}

func TestAnalyze_ZeroContainerPodWarnsAndSkips(t *testing.T) {
	pod := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "kube-apiserver-broken",
			"namespace": "kube-system",
			"labels":    map[string]any{"component": "kube-apiserver", "tier": "control-plane"},
		},
		"spec": map[string]any{
			"containers": []any{},
		},
	}}

	var warnings []string
	res, err := Analyze([]loader.Resource{{Object: pod, Source: "cluster:test"}}, "cluster:test",
		func(format string, args ...any) { warnings = append(warnings, format) })
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected exactly one warning for a classified Pod with zero containers, got %v", warnings)
	}
	if len(res.Observed) != 0 {
		t.Errorf("expected the component to not be marked observed when it couldn't actually be checked, got %v", res.Observed)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings from an unchecked Pod, got %+v", res.Findings)
	}
}

func namespaceResource(name string, labels map[string]string) loader.Resource {
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name": name,
		},
	}
	if labels != nil {
		l := map[string]any{}
		for k, v := range labels {
			l[k] = v
		}
		obj["metadata"].(map[string]any)["labels"] = l
	}
	return loader.Resource{Object: &unstructured.Unstructured{Object: obj}, Source: "test"}
}

func TestNamespacePSAEnforcement_LabelMissingFlagged(t *testing.T) {
	resources := []loader.Resource{
		namespaceResource("no-label", nil),
		namespaceResource("has-label", map[string]string{"pod-security.kubernetes.io/enforce": "baseline"}),
	}
	res, err := Analyze(resources, "test", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	var flaggedNamespaces []string
	for _, f := range res.Findings {
		if f.PolicyID == PSACheckID {
			flaggedNamespaces = append(flaggedNamespaces, f.Resource.Name)
		}
	}
	if len(flaggedNamespaces) != 1 || flaggedNamespaces[0] != "no-label" {
		t.Errorf("expected only 'no-label' namespace flagged, got %v", flaggedNamespaces)
	}
}

// TestNamespacePSAEnforcement_ClusterWideConfigFileSuppressesFindings covers
// exactly the false-positive this check exists to avoid: a cluster that
// enables Pod Security Admission cluster-wide via
// --admission-control-config-file needs no per-namespace labels at all, and
// this check must not flag every unlabeled namespace as non-compliant.
func TestNamespacePSAEnforcement_ClusterWideConfigFileSuppressesFindings(t *testing.T) {
	resources := []loader.Resource{
		apiserverPod("kube-apiserver-node1", "--admission-control-config-file=/etc/kubernetes/admission/config.yaml"),
		namespaceResource("no-label", nil),
	}
	res, err := Analyze(resources, "test", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range res.Findings {
		if f.PolicyID == PSACheckID {
			t.Errorf("expected no PSA-enforcement findings when --admission-control-config-file is set, got %+v", f)
		}
	}
}

func TestAdmissionPluginNotDisabledDefaultsToPass(t *testing.T) {
	eval := admissionPluginNotDisabled("NodeRestriction")
	if ok, _ := eval(flags{}); !ok {
		t.Error("expected an unset --enable-admission-plugins to pass (compiled-in default applies)")
	}
	if ok, _ := eval(flags{"enable-admission-plugins": {"ServiceAccount"}}); ok {
		t.Error("expected an explicit --enable-admission-plugins that omits NodeRestriction to fail")
	}
	if ok, _ := eval(flags{"disable-admission-plugins": {"NodeRestriction"}}); ok {
		t.Error("expected an explicit --disable-admission-plugins that includes NodeRestriction to fail")
	}
}
