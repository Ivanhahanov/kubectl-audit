package automation

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

type fakeClusters struct{ clusters []storage.Cluster }

func (f *fakeClusters) Register(context.Context, string, string, string, string) (storage.Cluster, error) {
	return storage.Cluster{}, nil
}
func (f *fakeClusters) GetByID(context.Context, uuid.UUID) (storage.Cluster, error) {
	return storage.Cluster{}, storage.ErrNotFound
}
func (f *fakeClusters) GetByTokenHash(context.Context, string) (storage.Cluster, error) {
	return storage.Cluster{}, storage.ErrNotFound
}
func (f *fakeClusters) ListClusters(context.Context) ([]storage.Cluster, error) {
	return f.clusters, nil
}

type recordingExecutor struct{ executed []Match }

func (r *recordingExecutor) Execute(_ context.Context, m Match) (ExecutionResult, error) {
	r.executed = append(r.executed, m)
	return ExecutionResult{Match: m, Attempted: false, Detail: "recorded"}, nil
}

func TestRunner_RunOnce_EvaluatesEveryCluster(t *testing.T) {
	clusterA := uuid.New()
	clusterB := uuid.New()
	rule := storage.AutomationRule{Name: "any critical", Enabled: true, Trigger: storage.AutomationTrigger{MinSeverity: "CRITICAL"}}

	findingsByCluster := map[uuid.UUID][]storage.Finding{
		clusterA: {{ClusterID: clusterA, Source: "kubectl-audit", Fingerprint: "a1", Severity: "CRITICAL"}},
		clusterB: {{ClusterID: clusterB, Source: "kubectl-audit", Fingerprint: "b1", Severity: "LOW"}},
	}

	executor := &recordingExecutor{}
	runner := &Runner{
		Clusters: &fakeClusters{clusters: []storage.Cluster{{ID: clusterA}, {ID: clusterB}}},
		Evaluator: &Evaluator{
			Rules:    &fakeRules{rules: []storage.AutomationRule{rule}},
			Findings: &multiClusterFakeFindings{byCluster: findingsByCluster},
			Triage:   &fakeTriage{},
		},
		Executor: executor,
	}

	results, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1 (only clusterA's finding is CRITICAL)", len(results))
	}
	if results[0].Match.ClusterID != clusterA {
		t.Errorf("matched cluster = %v, want %v", results[0].Match.ClusterID, clusterA)
	}
}

// multiClusterFakeFindings scopes ListFindings by clusterID, unlike
// fakeFindings (which ignores it) — needed here since the whole point of
// this test is per-cluster isolation.
type multiClusterFakeFindings struct {
	byCluster map[uuid.UUID][]storage.Finding
}

func (f *multiClusterFakeFindings) IngestScan(context.Context, storage.Scan, []storage.Finding) (storage.Scan, error) {
	return storage.Scan{}, nil
}
func (f *multiClusterFakeFindings) GetFinding(context.Context, uuid.UUID, string, string) (storage.Finding, error) {
	return storage.Finding{}, storage.ErrNotFound
}
func (f *multiClusterFakeFindings) ListFindings(_ context.Context, clusterID uuid.UUID, _ storage.FindingFilter) ([]storage.Finding, error) {
	return f.byCluster[clusterID], nil
}
func (f *multiClusterFakeFindings) ListByResource(context.Context, uuid.UUID, string, string, string) ([]storage.Finding, error) {
	return nil, nil
}
func (f *multiClusterFakeFindings) ListScans(context.Context, uuid.UUID) ([]storage.Scan, error) {
	return nil, nil
}

func TestLogExecutor_RecordsButDoesNotAttempt(t *testing.T) {
	var logged string
	exec := LogExecutor{Logf: func(format string, args ...any) { logged = format }}
	m := Match{
		ClusterID: uuid.New(),
		Rule:      storage.AutomationRule{Name: "r", Action: storage.AutomationAction{Type: "file_jira"}},
		Finding:   storage.Finding{Source: "kubectl-audit", Fingerprint: "f1"},
	}
	res, err := exec.Execute(context.Background(), m)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Attempted {
		t.Error("Attempted = true, want false — file_jira has no real implementation yet")
	}
	if logged == "" {
		t.Error("expected LogExecutor to log something")
	}
}
