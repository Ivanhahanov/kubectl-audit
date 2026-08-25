package pss

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// TestEveryCheckHasVerificationSteps guards the triage-tool content
// requirement (see docs/triage.md): both known check IDs (baseline,
// restricted) must produce findings with a non-empty VerificationSteps.
func TestEveryCheckHasVerificationSteps(t *testing.T) {
	baseline, err := Analyze([]loader.Resource{privilegedPod("bad")}, "test", "", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	restricted, err := Analyze([]loader.Resource{restrictedViolatingPod("mid")}, "test", "", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	want := map[string]bool{CheckIDBaseline: false, CheckIDRestricted: false}
	for _, f := range append(baseline, restricted...) {
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
