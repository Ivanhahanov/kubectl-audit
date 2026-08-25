package apideprecations_test

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/apideprecations"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// TestEveryCheckHasVerificationSteps guards the triage-tool content
// requirement (see docs/triage.md): the sole check ID must produce
// findings with a non-empty VerificationSteps.
func TestEveryCheckHasVerificationSteps(t *testing.T) {
	out := apideprecations.Analyze([]loader.Resource{resource("extensions/v1beta1", "Ingress", "old")}, "v1.25.0", "test")
	if len(out) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", out)
	}
	if out[0].PolicyID != apideprecations.CheckID {
		t.Fatalf("expected PolicyID %q, got %q", apideprecations.CheckID, out[0].PolicyID)
	}
	if out[0].VerificationSteps == "" {
		t.Errorf("finding %s has no VerificationSteps", out[0].PolicyID)
	}
}
