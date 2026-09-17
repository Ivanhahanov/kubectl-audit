package automation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

// fakeRules/fakeFindings/fakeTriage are minimal in-memory doubles — the
// Evaluator only calls List*, so every other interface method is an unused
// stub required purely to satisfy the interface type.
type fakeRules struct{ rules []storage.AutomationRule }

func (f *fakeRules) CreateAutomationRule(context.Context, storage.AutomationRule) (storage.AutomationRule, error) {
	return storage.AutomationRule{}, nil
}
func (f *fakeRules) GetAutomationRule(context.Context, uuid.UUID) (storage.AutomationRule, error) {
	return storage.AutomationRule{}, nil
}
func (f *fakeRules) ListAutomationRules(context.Context) ([]storage.AutomationRule, error) {
	return f.rules, nil
}
func (f *fakeRules) UpdateAutomationRule(context.Context, storage.AutomationRule) error { return nil }
func (f *fakeRules) DeleteAutomationRule(context.Context, uuid.UUID) error              { return nil }

type fakeFindings struct{ findings []storage.Finding }

func (f *fakeFindings) IngestScan(context.Context, storage.Scan, []storage.Finding) (storage.Scan, error) {
	return storage.Scan{}, nil
}
func (f *fakeFindings) GetFinding(context.Context, uuid.UUID, string, string) (storage.Finding, error) {
	return storage.Finding{}, storage.ErrNotFound
}
func (f *fakeFindings) ListFindings(context.Context, uuid.UUID, storage.FindingFilter) ([]storage.Finding, error) {
	return f.findings, nil
}
func (f *fakeFindings) ListByResource(context.Context, uuid.UUID, string, string, string) ([]storage.Finding, error) {
	return nil, nil
}
func (f *fakeFindings) ListScans(context.Context, uuid.UUID) ([]storage.Scan, error) { return nil, nil }

type fakeTriage struct{ entries []storage.TriageEntry }

func (f *fakeTriage) GetTriageEntry(context.Context, uuid.UUID, string, string) (storage.TriageEntry, bool, error) {
	return storage.TriageEntry{}, false, nil
}
func (f *fakeTriage) UpsertTriageEntry(context.Context, storage.TriageEntry) error { return nil }
func (f *fakeTriage) ListTriageEntries(context.Context, uuid.UUID) ([]storage.TriageEntry, error) {
	return f.entries, nil
}

func TestEvaluator_MatchesOnSeverityAndStatus(t *testing.T) {
	clusterID := uuid.New()
	rule := storage.AutomationRule{
		Name: "critical confirmed", Enabled: true,
		Trigger: storage.AutomationTrigger{MinSeverity: "CRITICAL", Status: "confirmed"},
		Action:  storage.AutomationAction{Type: "file_jira"},
	}
	criticalFinding := storage.Finding{ClusterID: clusterID, Source: "kubectl-audit", Fingerprint: "f1", Severity: "CRITICAL"}
	highFinding := storage.Finding{ClusterID: clusterID, Source: "kubectl-audit", Fingerprint: "f2", Severity: "HIGH"}
	unconfirmedCritical := storage.Finding{ClusterID: clusterID, Source: "kubectl-audit", Fingerprint: "f3", Severity: "CRITICAL"}

	e := &Evaluator{
		Rules:    &fakeRules{rules: []storage.AutomationRule{rule}},
		Findings: &fakeFindings{findings: []storage.Finding{criticalFinding, highFinding, unconfirmedCritical}},
		Triage: &fakeTriage{entries: []storage.TriageEntry{
			{ClusterID: clusterID, Source: "kubectl-audit", Fingerprint: "f1", Status: storage.TriageStatusConfirmed},
			{ClusterID: clusterID, Source: "kubectl-audit", Fingerprint: "f2", Status: storage.TriageStatusConfirmed},
			{ClusterID: clusterID, Source: "kubectl-audit", Fingerprint: "f3", Status: storage.TriageStatusNew},
		}},
	}

	matches, err := e.EvaluateCluster(context.Background(), clusterID, time.Now())
	if err != nil {
		t.Fatalf("EvaluateCluster: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("len(matches) = %d, want 1 (only f1: critical + confirmed)", len(matches))
	}
	if matches[0].Finding.Fingerprint != "f1" {
		t.Errorf("matched fingerprint = %q, want f1", matches[0].Finding.Fingerprint)
	}
}

func TestEvaluator_DisabledRuleNeverMatches(t *testing.T) {
	clusterID := uuid.New()
	rule := storage.AutomationRule{Name: "disabled", Enabled: false, Trigger: storage.AutomationTrigger{}}
	e := &Evaluator{
		Rules:    &fakeRules{rules: []storage.AutomationRule{rule}},
		Findings: &fakeFindings{findings: []storage.Finding{{ClusterID: clusterID, Source: "x", Fingerprint: "f1", Severity: "CRITICAL"}}},
		Triage:   &fakeTriage{},
	}
	matches, err := e.EvaluateCluster(context.Background(), clusterID, time.Now())
	if err != nil {
		t.Fatalf("EvaluateCluster: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("len(matches) = %d, want 0 (rule is disabled)", len(matches))
	}
}

func TestEvaluator_NoJiraLinkForHours(t *testing.T) {
	clusterID := uuid.New()
	rule := storage.AutomationRule{
		Name: "stale confirmed", Enabled: true,
		Trigger: storage.AutomationTrigger{Status: "confirmed", NoJiraLinkForHours: 24},
	}
	now := time.Now()

	tests := []struct {
		name    string
		entry   storage.TriageEntry
		wantHit bool
	}{
		{"recently confirmed, no jira link", storage.TriageEntry{Status: storage.TriageStatusConfirmed, UpdatedAt: now.Add(-1 * time.Hour)}, false},
		{"stale confirmed, no jira link", storage.TriageEntry{Status: storage.TriageStatusConfirmed, UpdatedAt: now.Add(-48 * time.Hour)}, true},
		{"stale confirmed, already has a jira link", storage.TriageEntry{Status: storage.TriageStatusConfirmed, UpdatedAt: now.Add(-48 * time.Hour), JiraIssueKey: "SEC-1"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.entry.ClusterID, tt.entry.Source, tt.entry.Fingerprint = clusterID, "kubectl-audit", "f1"
			e := &Evaluator{
				Rules:    &fakeRules{rules: []storage.AutomationRule{rule}},
				Findings: &fakeFindings{findings: []storage.Finding{{ClusterID: clusterID, Source: "kubectl-audit", Fingerprint: "f1"}}},
				Triage:   &fakeTriage{entries: []storage.TriageEntry{tt.entry}},
			}
			matches, err := e.EvaluateCluster(context.Background(), clusterID, now)
			if err != nil {
				t.Fatalf("EvaluateCluster: %v", err)
			}
			if got := len(matches) == 1; got != tt.wantHit {
				t.Errorf("matched = %v, want %v", got, tt.wantHit)
			}
		})
	}
}

func TestEvaluator_UntouchedFindingDefaultsToStatusNew(t *testing.T) {
	clusterID := uuid.New()
	rule := storage.AutomationRule{Name: "new findings", Enabled: true, Trigger: storage.AutomationTrigger{Status: "new"}}
	e := &Evaluator{
		Rules:    &fakeRules{rules: []storage.AutomationRule{rule}},
		Findings: &fakeFindings{findings: []storage.Finding{{ClusterID: clusterID, Source: "kubectl-audit", Fingerprint: "f1"}}},
		Triage:   &fakeTriage{}, // no entry at all for f1
	}
	matches, err := e.EvaluateCluster(context.Background(), clusterID, time.Now())
	if err != nil {
		t.Fatalf("EvaluateCluster: %v", err)
	}
	if len(matches) != 1 {
		t.Errorf("len(matches) = %d, want 1 (an untriaged finding is implicitly status=new)", len(matches))
	}
}
