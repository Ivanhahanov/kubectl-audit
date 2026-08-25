package engine_test

// TestEveryBuiltinPolicyHasVerificationSteps guards the triage-tool content
// requirement: every bundled policy must carry an
// audit.k8s-auditor.io/verification-steps annotation (parsed into
// PolicyMeta.VerificationSteps, see internal/engine/vap.go) telling a human
// triaging a finding how to confirm it's a true positive in their specific
// environment — see docs/triage.md. Guards against a new policy being added
// without this annotation, silently missing the same triage guidance every
// other bundled check carries.
import (
	"strings"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/engine"
)

func TestEveryBuiltinPolicyHasVerificationSteps(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	if len(policies) == 0 {
		t.Fatal("LoadBuiltin returned no policies — test setup is broken, not the code under test")
	}

	for _, p := range policies {
		steps := strings.TrimSpace(p.Meta.VerificationSteps)
		if steps == "" {
			t.Errorf("policy %q has no audit.k8s-auditor.io/verification-steps annotation", p.Meta.ID)
			continue
		}
		if len(steps) < 40 {
			t.Errorf("policy %q's verification-steps annotation is suspiciously short (%d chars: %q) — looks like a placeholder, not real guidance", p.Meta.ID, len(steps), steps)
		}
	}
}
