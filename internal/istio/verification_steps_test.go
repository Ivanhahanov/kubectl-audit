package istio_test

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/istio"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// TestEveryCheckHasVerificationSteps guards the triage-tool content
// requirement (see docs/triage.md): CheckID must produce findings with a
// non-empty VerificationSteps.
func TestEveryCheckHasVerificationSteps(t *testing.T) {
	resources := []loader.Resource{
		namespace("payments", map[string]string{"istio-injection": "enabled"}),
		meshPod(),
	}
	found, err := istio.AnalyzeAuthorizationCoverage(resources, "test")
	if err != nil {
		t.Fatalf("AnalyzeAuthorizationCoverage: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("expected at least one finding from this fixture set")
	}
	for _, f := range found {
		if f.VerificationSteps == "" {
			t.Errorf("finding %s has no VerificationSteps", f.PolicyID)
		}
	}
}
