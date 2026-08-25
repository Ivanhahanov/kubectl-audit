package secrets_test

import (
	"testing"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/secrets"
)

// TestEveryCheckHasVerificationSteps guards the triage-tool content
// requirement (see docs/triage.md): all three known check IDs
// (weak-credential-value, value-reused-across-objects,
// not-rotated-recently) must produce findings with a non-empty
// VerificationSteps.
func TestEveryCheckHasVerificationSteps(t *testing.T) {
	weak := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: weak-secret
  namespace: default
stringData:
  password: password
`)
	reusedA := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: reused-a
  namespace: default
stringData:
  token: a-real-looking-shared-value-123456
`)
	reusedB := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: reused-b
  namespace: default
stringData:
  token: a-real-looking-shared-value-123456
`)
	stale := mustResource(t, `
apiVersion: v1
kind: Secret
metadata:
  name: stale-secret
  namespace: default
  creationTimestamp: "2020-01-01T00:00:00Z"
data: {}
`)

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	found, err := secrets.AnalyzeAt([]loader.Resource{weak, reusedA, reusedB, stale}, "test", now)
	if err != nil {
		t.Fatalf("AnalyzeAt: %v", err)
	}

	want := map[string]bool{
		"secrets-analyzer.weak-credential-value":       false,
		"secrets-analyzer.value-reused-across-objects": false,
		"secrets-analyzer.not-rotated-recently":        false,
	}
	for _, f := range found {
		if _, known := want[f.PolicyID]; known {
			want[f.PolicyID] = true
		}
		if f.VerificationSteps == "" {
			t.Errorf("finding %s has no VerificationSteps", f.PolicyID)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("expected a %s finding from this fixture set", id)
		}
	}
}
