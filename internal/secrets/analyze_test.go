package secrets_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/secrets"
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

func TestAnalyze_WeakValueDetectsShortAndLowEntropyCredentials(t *testing.T) {
	shortSecret := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app
  namespace: default
data:
  password: `+b64("abc1")+`
`)
	lowEntropySecret := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app2
  namespace: default
data:
  password: `+b64(strings.Repeat("aaaaaaaa", 3))+`
`)
	strongSecret := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app3
  namespace: default
data:
  password: `+b64("Zk9wLXY3TXFSNXZUOFBtSDNuWHlBMmNFN2dCNGZOUXI=")+`
`)

	got, err := secrets.Analyze([]loader.Resource{shortSecret, lowEntropySecret, strongSecret}, "test")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	weak := findingsForPolicy(got, "secrets-analyzer.weak-credential-value")
	if len(weak) != 2 {
		t.Fatalf("expected 2 weak-value findings (short + low-entropy), got %d: %+v", len(weak), weak)
	}
	for _, f := range weak {
		if f.Resource.Name == "app3" {
			t.Errorf("did not expect the strong-looking secret to be flagged")
		}
	}
}

func TestAnalyze_IgnoresNonCredentialKeys(t *testing.T) {
	sec := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app
  namespace: default
data:
  enabled: `+b64("true")+`
  port: `+b64("80")+`
`)
	got, err := secrets.Analyze([]loader.Resource{sec}, "test")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no findings on non-credential-shaped keys, got %+v", got)
	}
}

// TestAnalyze_ReadsStringData guards a real gap found by an adversarial
// stress-test pass: a Secret authored with stringData (the common,
// human-friendly way to write a Secret by hand — no manual base64 step —
// and a mainstream pattern in static manifests/GitOps repos, this tool's
// other primary scan mode) was previously invisible to this whole package,
// which only ever read .data.
func TestAnalyze_ReadsStringData(t *testing.T) {
	sec := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app
  namespace: default
stringData:
  password: changeme
`)
	got, err := secrets.Analyze([]loader.Resource{sec}, "test")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	weak := findingsForPolicy(got, "secrets-analyzer.weak-credential-value")
	if len(weak) == 0 {
		t.Errorf("expected a weak-value finding on a stringData-authored Secret, got %+v", got)
	}
}

// TestAnalyze_ChecksBasicAuthTypedSecrets guards the other gap found by the
// same pass: kubernetes.io/basic-auth is a real, built-in Kubernetes type
// whose data is literally username/password — the same flat-credential
// shape as Opaque — but was wrongly excluded alongside the genuinely
// structurally-different typed Secrets (tls, dockerconfigjson, ...).
func TestAnalyze_ChecksBasicAuthTypedSecrets(t *testing.T) {
	sec := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app
  namespace: default
type: kubernetes.io/basic-auth
data:
  username: `+b64("admin")+`
  password: `+b64("password")+`
`)
	got, err := secrets.Analyze([]loader.Resource{sec}, "test")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	weak := findingsForPolicy(got, "secrets-analyzer.weak-credential-value")
	if len(weak) == 0 {
		t.Errorf("expected a weak-value finding on a kubernetes.io/basic-auth Secret's password field, got %+v", got)
	}
}

// TestAnalyze_ReuseDetectionUnifiesDataAndStringDataEncodings guards the
// switch from comparing raw base64 strings to comparing decoded plaintext
// for reuse detection — a value authored as stringData in one Secret and
// as base64 .data in another must still be recognized as the same reused
// value.
func TestAnalyze_ReuseDetectionUnifiesDataAndStringDataEncodings(t *testing.T) {
	secretA := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: service-a
  namespace: default
stringData:
  apiToken: a-real-looking-random-value-shared-by-mistake-123
`)
	secretB := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: service-b
  namespace: default
data:
  apiToken: `+b64("a-real-looking-random-value-shared-by-mistake-123")+`
`)
	got, err := secrets.Analyze([]loader.Resource{secretA, secretB}, "test")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	reused := findingsForPolicy(got, "secrets-analyzer.value-reused-across-objects")
	if len(reused) != 2 {
		t.Fatalf("expected reuse detection to unify a stringData value with the same value's base64 .data form, got %d: %+v", len(reused), reused)
	}
	for _, f := range reused {
		if strings.Contains(f.Message, f.Resource.Namespace+"/"+f.Resource.Name+":"+"apiToken") {
			t.Errorf("finding cites itself in its own \"same as\" list: %s", f.Message)
		}
	}
}

func TestAnalyze_IgnoresTypedSecrets(t *testing.T) {
	tlsSecret := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app-tls
  namespace: default
type: kubernetes.io/tls
data:
  tls.crt: `+b64("abc")+`
  tls.key: `+b64("abc")+`
`)
	got, err := secrets.Analyze([]loader.Resource{tlsSecret}, "test")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no findings on a kubernetes.io/tls-typed Secret, got %+v", got)
	}
}

func TestAnalyze_IgnoresPublicKeyNamedFields(t *testing.T) {
	sec := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app
  namespace: default
data:
  publicKey: `+b64("abc")+`
`)
	got, err := secrets.Analyze([]loader.Resource{sec}, "test")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no findings on a publicKey-named field even though it contains \"key\", got %+v", got)
	}
}

func TestAnalyze_DetectsValueReusedAcrossDistinctSecrets(t *testing.T) {
	shared := b64("a-real-looking-random-value-shared-by-mistake-123")
	secretA := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: service-a
  namespace: default
data:
  apiToken: `+shared+`
`)
	secretB := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: service-b
  namespace: default
data:
  apiToken: `+shared+`
`)

	got, err := secrets.Analyze([]loader.Resource{secretA, secretB}, "test")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	reused := findingsForPolicy(got, "secrets-analyzer.value-reused-across-objects")
	if len(reused) != 2 {
		t.Fatalf("expected one finding per object sharing the value (2 total), got %d: %+v", len(reused), reused)
	}
}

func TestAnalyze_DoesNotFlagTheSameSecretMirroringItsOwnValueAcrossKeys(t *testing.T) {
	shared := b64("a-real-looking-random-value-mirrored-on-purpose")
	sec := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: db
  namespace: default
data:
  password: `+shared+`
  replicationPassword: `+shared+`
`)
	got, err := secrets.Analyze([]loader.Resource{sec}, "test")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	reused := findingsForPolicy(got, "secrets-analyzer.value-reused-across-objects")
	if len(reused) != 0 {
		t.Errorf("expected no reuse finding for one Secret mirroring its own value across two of its own keys, got %+v", reused)
	}
}

func TestAnalyze_IgnoresShortCoincidentalReuse(t *testing.T) {
	shared := b64("short")
	secretA := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: service-a
  namespace: default
data:
  token: `+shared+`
`)
	secretB := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: service-b
  namespace: default
data:
  token: `+shared+`
`)
	got, err := secrets.Analyze([]loader.Resource{secretA, secretB}, "test")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	// "short" is 5 bytes decoded, below minReuseValueLength — should not
	// be reported as reuse (though it may still be reported as weak).
	reused := findingsForPolicy(got, "secrets-analyzer.value-reused-across-objects")
	if len(reused) != 0 {
		t.Errorf("expected no reuse finding for a trivially short shared value, got %+v", reused)
	}
}

// TestFindingsNeverEmbedSecretValues is the anti-leak guarantee this
// package's doc comment promises: no finding this package ever produces —
// across every scenario the rest of this file exercises — may contain the
// base64 form (or the decoded plaintext form) of any input Secret value
// anywhere in its Title/Message/Remediation/VerificationSteps. Unlike the CEL engine's
// secret-targeting policies (which are structurally prevented from this by
// forbidding messageExpression), this package builds findings directly in
// Go, so the guarantee has to be verified by inspection, not assumed from
// the absence of a language feature.
func TestFindingsNeverEmbedSecretValues(t *testing.T) {
	secretValues := []string{
		"abc1",
		strings.Repeat("aaaaaaaa", 3),
		"a-real-looking-random-value-shared-by-mistake-123",
		"a-real-looking-random-value-mirrored-on-purpose",
	}

	resources := []loader.Resource{
		mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app
  namespace: default
data:
  password: `+b64("abc1")+`
`),
		mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: app2
  namespace: default
data:
  password: `+b64(strings.Repeat("aaaaaaaa", 3))+`
`),
		mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: service-a
  namespace: default
data:
  apiToken: `+b64("a-real-looking-random-value-shared-by-mistake-123")+`
`),
		mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: service-b
  namespace: default
data:
  apiToken: `+b64("a-real-looking-random-value-shared-by-mistake-123")+`
`),
		mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: db
  namespace: default
data:
  password: `+b64("a-real-looking-random-value-mirrored-on-purpose")+`
  replicationPassword: `+b64("a-real-looking-random-value-mirrored-on-purpose")+`
`),
	}

	got, err := secrets.Analyze(resources, "test")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected at least one finding to actually exercise the leak check")
	}
	for _, f := range got {
		blob := f.Title + " " + f.Message + " " + f.Remediation + " " + f.VerificationSteps
		for _, v := range secretValues {
			if strings.Contains(blob, v) {
				t.Errorf("finding %s leaks a secret value: %q appears in %q", f.PolicyID, v, blob)
			}
			if strings.Contains(blob, base64.StdEncoding.EncodeToString([]byte(v))) {
				t.Errorf("finding %s leaks a secret value's base64 form in %q", f.PolicyID, blob)
			}
		}
	}
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestAnalyzeAt_FlagsSecretsNotRotatedInOverAYear(t *testing.T) {
	old := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: old-secret
  namespace: default
  creationTimestamp: "2020-01-01T00:00:00Z"
data: {}
`)
	recent := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: recent-secret
  namespace: default
  creationTimestamp: "2026-08-01T00:00:00Z"
data: {}
`)
	now, err := time.Parse(time.RFC3339, "2026-08-21T00:00:00Z")
	if err != nil {
		t.Fatalf("parsing test 'now': %v", err)
	}

	got, err := secrets.AnalyzeAt([]loader.Resource{old, recent}, "test", now)
	if err != nil {
		t.Fatalf("AnalyzeAt: %v", err)
	}
	stale := findingsForPolicy(got, "secrets-analyzer.not-rotated-recently")
	if len(stale) != 1 {
		t.Fatalf("expected exactly 1 stale-secret finding, got %d: %+v", len(stale), stale)
	}
	if stale[0].Resource.Name != "old-secret" {
		t.Errorf("expected the finding to be on old-secret, got %s", stale[0].Resource.Name)
	}
	if stale[0].Severity != findings.SeverityLow {
		t.Errorf("expected Low severity, got %s", stale[0].Severity)
	}
}

func TestAnalyzeAt_AppliesToNonOpaqueSecretsToo(t *testing.T) {
	old := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: old-tls
  namespace: default
  creationTimestamp: "2020-01-01T00:00:00Z"
type: kubernetes.io/tls
data:
  tls.crt: `+b64("abc")+`
  tls.key: `+b64("abc")+`
`)
	now, _ := time.Parse(time.RFC3339, "2026-08-21T00:00:00Z")

	got, err := secrets.AnalyzeAt([]loader.Resource{old}, "test", now)
	if err != nil {
		t.Fatalf("AnalyzeAt: %v", err)
	}
	if len(findingsForPolicy(got, "secrets-analyzer.not-rotated-recently")) != 1 {
		t.Errorf("expected the age check to apply to a kubernetes.io/tls Secret too, got %+v", got)
	}
	// But the value-based checks must still skip it (typed, not Opaque).
	if len(got) != 1 {
		t.Errorf("expected only the age finding for a typed Secret, got %d: %+v", len(got), got)
	}
}
