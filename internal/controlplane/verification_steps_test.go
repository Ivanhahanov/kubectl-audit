package controlplane

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// TestEveryCheckHasVerificationSteps guards the triage-tool content
// requirement (see docs/triage.md): every checks.go entry plus the
// PSACheckID must produce findings with a non-empty VerificationSteps.
func TestEveryCheckHasVerificationSteps(t *testing.T) {
	resources := []loader.Resource{
		apiserverPod("kube-apiserver-node1",
			"--authorization-mode=AlwaysAllow",
			"--enable-admission-plugins=AlwaysAdmit",
			"--audit-log-maxage=1",
			"--audit-log-maxbackup=1",
			"--audit-log-maxsize=1",
		),
		namespaceResource("no-psa-label", nil),
	}
	res, err := Analyze(resources, "test", nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	want := map[string]bool{}
	for _, c := range checks {
		want[c.ID] = false
	}
	want[PSACheckID] = false

	for _, f := range res.Findings {
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
