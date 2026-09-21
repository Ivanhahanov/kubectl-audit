package cni_test

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/cni"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// TestEveryCheckHasVerificationSteps guards the triage-tool content
// requirement (see docs/triage.md): CheckID must produce findings with a
// non-empty VerificationSteps.
func TestEveryCheckHasVerificationSteps(t *testing.T) {
	found := cni.Analyze([]loader.Resource{
		daemonSet("kube-flannel-ds", map[string]string{"app": "flannel"}),
	}, "test")

	if len(found) == 0 {
		t.Fatal("expected at least one finding from this fixture set")
	}
	for _, f := range found {
		if f.PolicyID != cni.CheckID {
			continue
		}
		if f.VerificationSteps == "" {
			t.Errorf("finding %s has no VerificationSteps", f.PolicyID)
		}
	}
}
