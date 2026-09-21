package quota_test

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/quota"
)

// TestEveryCheckHasVerificationSteps guards the triage-tool content
// requirement (see docs/triage.md): both known check IDs must produce
// findings with a non-empty VerificationSteps.
func TestEveryCheckHasVerificationSteps(t *testing.T) {
	found := quota.Analyze([]loader.Resource{namespace("app-team", nil)}, "test")

	want := map[string]bool{
		quota.CheckIDNoResourceQuota: false,
		quota.CheckIDNoLimitRange:    false,
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
