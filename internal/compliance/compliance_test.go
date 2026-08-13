package compliance_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/compliance"
	"github.com/ivanhahanov/kubectl-audit/internal/engine"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

func boolPtr(b bool) *bool { return &b }

func TestBuildScorecardStatuses(t *testing.T) {
	mapping := &compliance.Mapping{
		ID: "test", Title: "Test Framework", Version: "1",
		Controls: []compliance.Control{
			{ID: "na", Applicable: false, NAReason: "needs node access"},
			{ID: "ni", Applicable: true, Implemented: boolPtr(false), Note: "not built yet"},
			{ID: "pass", Applicable: true, PolicyIDs: []string{"workload.no-such-finding"}},
			{ID: "fail", Applicable: true, PolicyIDs: []string{"workload.bad"}},
		},
	}
	findingsList := []findings.Finding{
		{ID: "f1", PolicyID: "workload.bad", Resource: findings.ResourceRef{Kind: "Pod", Name: "p"}},
	}

	sc := compliance.BuildScorecard(mapping, findingsList)
	if sc.ID != "test" || sc.Title != "Test Framework" || sc.Version != "1" {
		t.Fatalf("expected scorecard metadata to carry through from the mapping, got %+v", sc)
	}
	if len(sc.Results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(sc.Results))
	}

	byID := map[string]compliance.ControlResult{}
	for _, r := range sc.Results {
		byID[r.Control.ID] = r
	}

	if byID["na"].Status != compliance.StatusNotApplicable {
		t.Errorf("expected 'na' control to be NOT_APPLICABLE, got %s", byID["na"].Status)
	}
	if byID["ni"].Status != compliance.StatusNotImplemented {
		t.Errorf("expected 'ni' control to be NOT_IMPLEMENTED, got %s", byID["ni"].Status)
	}
	if byID["pass"].Status != compliance.StatusPass {
		t.Errorf("expected 'pass' control to PASS, got %s", byID["pass"].Status)
	}
	failRes := byID["fail"]
	if failRes.Status != compliance.StatusFail {
		t.Errorf("expected 'fail' control to FAIL, got %s", failRes.Status)
	}
	if len(failRes.FindingIDs) != 1 || failRes.FindingIDs[0] != "f1" {
		t.Errorf("expected FAIL control to reference finding f1, got %v", failRes.FindingIDs)
	}
	if len(failRes.Resources) != 1 || failRes.Resources[0].Name != "p" {
		t.Errorf("expected FAIL control to list the affected resource, got %v", failRes.Resources)
	}
}

func TestSummarize(t *testing.T) {
	mapping := &compliance.Mapping{
		ID: "test", Title: "Test", Version: "1",
		Controls: []compliance.Control{
			{ID: "1", Applicable: false},
			{ID: "2", Applicable: true, Implemented: boolPtr(false)},
			{ID: "3", Applicable: true, PolicyIDs: []string{"never-matches"}},
			{ID: "4", Applicable: true, PolicyIDs: []string{"matches"}},
		},
	}
	sc := compliance.BuildScorecard(mapping, []findings.Finding{
		{ID: "f1", PolicyID: "matches", Resource: findings.ResourceRef{Kind: "Pod", Name: "p"}},
	})

	summaries := compliance.Summarize([]compliance.Scorecard{sc})
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	s := summaries[0]
	if s.Total != 4 || s.NotApplicable != 1 || s.NotImplemented != 1 || s.Pass != 1 || s.Fail != 1 {
		t.Errorf("unexpected summary counts: %+v", s)
	}
}

func TestLoadMappingKnownFrameworks(t *testing.T) {
	for _, id := range []string{"cis", "fstec", "nsa", "capsule"} {
		m, err := compliance.LoadMapping(id)
		if err != nil {
			t.Fatalf("LoadMapping(%q): %v", id, err)
		}
		if m.ID != id {
			t.Errorf("expected mapping id %q, got %q", id, m.ID)
		}
		if m.Title == "" || m.Version == "" {
			t.Errorf("mapping %q missing title/version: %+v", id, m)
		}
		if len(m.Controls) == 0 {
			t.Errorf("mapping %q has no controls", id)
		}
		for _, c := range m.Controls {
			if c.ID == "" || c.Title == "" || c.Section == "" {
				t.Errorf("mapping %q: control missing id/title/section: %+v", id, c)
			}
			if c.Applicable && !c.IsImplemented() && c.Note == "" {
				t.Errorf("mapping %q: control %q is NOT_IMPLEMENTED but has no explanatory note", id, c.ID)
			}
			if !c.Applicable && c.NAReason == "" {
				t.Errorf("mapping %q: control %q is NOT_APPLICABLE but has no naReason", id, c.ID)
			}
		}
	}
}

func TestOverrideUnobserved(t *testing.T) {
	mapping := &compliance.Mapping{
		ID: "test", Title: "Test", Version: "1",
		Controls: []compliance.Control{
			{ID: "observed", Applicable: true, NativeCheckIDs: []string{"controlplane-analyzer.apiserver.profiling"}},
			{ID: "unobserved", Applicable: true, NativeCheckIDs: []string{"controlplane-analyzer.etcd.auto-tls"}},
			{ID: "unobserved-vap", Applicable: true, PolicyIDs: []string{"controlplane.etcd.client-tls"}},
			{ID: "unrelated", Applicable: true, PolicyIDs: []string{"workload.no-privileged-containers"}},
		},
	}
	observed := map[string]bool{"apiserver": true}

	out := compliance.OverrideUnobserved(mapping, "controlplane-analyzer.", observed)

	byID := map[string]compliance.Control{}
	for _, c := range out.Controls {
		byID[c.ID] = c
	}
	if !byID["observed"].Applicable {
		t.Errorf("expected 'observed' control (apiserver, which is observed) to stay applicable, got %+v", byID["observed"])
	}
	if byID["unobserved"].Applicable {
		t.Errorf("expected 'unobserved' control (etcd, which is not observed) to become NOT_APPLICABLE, got %+v", byID["unobserved"])
	}
	if byID["unobserved"].NAReason == "" {
		t.Error("expected an naReason explaining why the control was forced NOT_APPLICABLE")
	}
	// This mapping call only used the native-check prefix; the VAP-style
	// policyIds-based control needs the separate "controlplane." prefix call
	// (see the second assertion below) — it must stay untouched here.
	if !byID["unobserved-vap"].Applicable {
		t.Errorf("expected the policyIds-based control to be untouched by the native-check-prefix call, got %+v", byID["unobserved-vap"])
	}
	if !byID["unrelated"].Applicable {
		t.Errorf("expected an unrelated (policyIds-based) control to be untouched, got %+v", byID["unrelated"])
	}

	// The VAP-style prefix call must catch policyIds-based controlplane
	// checks the same way — this is what the flag checks that moved from
	// nativeCheckIds to policyIds (see policies/controlplane/*.yaml) rely on.
	outVAP := compliance.OverrideUnobserved(mapping, "controlplane.", observed)
	byIDVAP := map[string]compliance.Control{}
	for _, c := range outVAP.Controls {
		byIDVAP[c.ID] = c
	}
	if byIDVAP["unobserved-vap"].Applicable {
		t.Errorf("expected the policyIds-based control for an unobserved component to become NOT_APPLICABLE, got %+v", byIDVAP["unobserved-vap"])
	}
	// mapping itself must not be mutated in place.
	if !mapping.Controls[1].Applicable {
		t.Error("OverrideUnobserved must not mutate the input mapping")
	}
}

func TestLoadMappingUnknownFramework(t *testing.T) {
	if _, err := compliance.LoadMapping("does-not-exist"); err == nil {
		t.Error("expected an error loading an unknown framework")
	}
}

func TestLoadMappingCustomPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "internal-standard.yaml")
	if err := os.WriteFile(path, []byte(`
id: internal
title: "Internal Example Standard"
version: "1"
controls:
  - id: "EX-01"
    title: "Example control"
    section: "Example"
    applicable: true
    policyIds: ["workload.no-privileged-containers"]
`), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	m, err := compliance.LoadMapping(path)
	if err != nil {
		t.Fatalf("LoadMapping(%q): %v", path, err)
	}
	if m.ID != "internal" || m.Title != "Internal Example Standard" {
		t.Errorf("unexpected mapping: %+v", m)
	}
	if len(m.Controls) != 1 || m.Controls[0].ID != "EX-01" {
		t.Errorf("unexpected controls: %+v", m.Controls)
	}
}

func TestLoadMappingCustomPathMissingFile(t *testing.T) {
	if _, err := compliance.LoadMapping("/nonexistent/dir/framework.yaml"); err == nil {
		t.Error("expected an error loading a nonexistent custom mapping path")
	}
}

func TestAvailableFrameworks(t *testing.T) {
	frameworks, err := compliance.AvailableFrameworks()
	if err != nil {
		t.Fatalf("AvailableFrameworks: %v", err)
	}
	want := map[string]bool{"cis": true, "fstec": true, "nsa": true}
	got := map[string]bool{}
	for _, f := range frameworks {
		got[f] = true
	}
	for id := range want {
		if !got[id] {
			t.Errorf("expected %q in AvailableFrameworks(), got %v", id, frameworks)
		}
	}
}

// TestMappedCheckIDsExist guards against typos in the mapping YAML files: every
// policyId must be a real bundled policy, and every nativeCheckId must be one
// of the known IDs emitted by the RBAC/NetworkPolicy analyzers.
func TestMappedCheckIDsExist(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	validPolicyIDs := map[string]bool{}
	for _, p := range policies {
		validPolicyIDs[p.Meta.ID] = true
	}

	// Kept in sync by hand with the finding() call sites in internal/rbac and
	// internal/netpol; a mismatch here should be caught by their own package
	// tests exercising each check, not just this list.
	validNativeCheckIDs := map[string]bool{
		"rbac-analyzer.escalation-verb":                   true,
		"rbac-analyzer.pod-exec-access":                   true,
		"rbac-analyzer.broad-secrets-access":              true,
		"rbac-analyzer.rbac-self-modification":            true,
		"rbac-analyzer.default-serviceaccount-bound":      true,
		"rbac-analyzer.automount-with-sensitive-access":   true,
		"rbac-analyzer.system-masters-usage":              true,
		"psa-analyzer.no-active-enforcement":              true,
		"version-analyzer.cluster.outside-support-window": true,
		"netpol-analyzer.no-network-policy-coverage":      true,

		// Simple presence/equals flag checks (kube-controller-manager,
		// kube-scheduler, etcd, and most of kube-apiserver's) moved to
		// policies/controlplane/*.yaml (VAP/CEL), matching validPolicyIDs
		// instead — only checks that need CSV-membership, cross-flag, or
		// numeric-threshold logic stayed Go-native.
		"controlplane-analyzer.apiserver.authz-always-allow":           true,
		"controlplane-analyzer.apiserver.authz-node":                   true,
		"controlplane-analyzer.apiserver.authz-rbac":                   true,
		"controlplane-analyzer.apiserver.always-admit":                 true,
		"controlplane-analyzer.apiserver.admission-serviceaccount":     true,
		"controlplane-analyzer.apiserver.admission-namespacelifecycle": true,
		"controlplane-analyzer.apiserver.admission-noderestriction":    true,
		"controlplane-analyzer.apiserver.audit-log-maxage":             true,
		"controlplane-analyzer.apiserver.audit-log-maxbackup":          true,
		"controlplane-analyzer.apiserver.audit-log-maxsize":            true,
	}

	for _, id := range []string{"cis", "fstec", "nsa", "capsule"} {
		m, err := compliance.LoadMapping(id)
		if err != nil {
			t.Fatalf("LoadMapping(%q): %v", id, err)
		}
		for _, c := range m.Controls {
			for _, pid := range c.PolicyIDs {
				if !validPolicyIDs[pid] {
					t.Errorf("%s control %s: policyId %q does not match any bundled policy", id, c.ID, pid)
				}
			}
			for _, nid := range c.NativeCheckIDs {
				if !validNativeCheckIDs[nid] {
					t.Errorf("%s control %s: nativeCheckId %q is not a known native check", id, c.ID, nid)
				}
			}
		}
	}
}
