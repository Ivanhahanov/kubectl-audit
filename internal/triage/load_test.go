package triage_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

func TestLoadFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.json")
	doc := `{
		"generatedAt": "2026-01-01T00:00:00Z",
		"target": "test",
		"summary": {"HIGH": 1},
		"findings": [
			{"id": "abc123", "policyId": "workload.no-latest-tag", "title": "t",
			 "severity": "HIGH", "category": "supply-chain",
			 "resource": {"kind": "Deployment", "namespace": "default", "name": "app"},
			 "message": "m", "verificationSteps": "check it"}
		],
		"suppressed": [
			{"finding": {"id": "sup1", "policyId": "workload.no-hostports", "title": "t2",
			 "severity": "MEDIUM", "category": "workload-security",
			 "resource": {"kind": "Pod", "namespace": "kube-system", "name": "cilium-agent"},
			 "message": "m2"},
			 "reason": "known cilium-agent exception"}
		]
	}`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	target, all, suppressed, err := triage.LoadFindings(path)
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if target != "test" {
		t.Errorf("expected target %q to round-trip, got %q", "test", target)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 active finding, got %d", len(all))
	}
	if all[0].ID != "abc123" || all[0].VerificationSteps != "check it" {
		t.Errorf("expected active finding fields to round-trip from real findings.json shape, got %+v", all[0])
	}
	if len(suppressed) != 1 {
		t.Fatalf("expected 1 suppressed finding, got %d", len(suppressed))
	}
	if suppressed[0].Finding.ID != "sup1" || suppressed[0].Reason != "known cilium-agent exception" {
		t.Errorf("expected suppressed finding + reason to round-trip, got %+v", suppressed[0])
	}
}

func TestLoadFindings_MissingFileErrors(t *testing.T) {
	_, _, _, err := triage.LoadFindings(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Error("expected an error for a missing findings.json — unlike triage state, there's no sensible empty default here")
	}
}
