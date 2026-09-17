package ingest

import (
	"os"
	"testing"

	"github.com/google/uuid"
)

func TestOpenReportsIngestor_Ingest_KyvernoFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/kyverno_policyreport.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	clusterID := uuid.New()
	batches, err := OpenReportsIngestor{}.Ingest(clusterID, body)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(batches) != 1 {
		t.Fatalf("len(batches) = %d, want 1 (single source: kyverno)", len(batches))
	}

	b := batches[0]
	if b.Scan.Source != "openreports:kyverno" {
		t.Errorf("Scan.Source = %q, want openreports:kyverno", b.Scan.Source)
	}
	if b.Scan.ClusterID != clusterID {
		t.Errorf("Scan.ClusterID = %v, want %v", b.Scan.ClusterID, clusterID)
	}

	// Only the "fail" result should become a finding — "pass" is dropped.
	if len(b.Findings) != 1 {
		t.Fatalf("len(b.Findings) = %d, want 1", len(b.Findings))
	}
	f := b.Findings[0]
	if f.PolicyID != "disallow-privileged-containers" {
		t.Errorf("PolicyID = %q", f.PolicyID)
	}
	if f.Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", f.Severity)
	}
	if f.ResourceKind != "Pod" || f.ResourceNamespace != "ci" || f.ResourceName != "buildkitd" {
		t.Errorf("resource = %q/%q/%q, want Pod/ci/buildkitd", f.ResourceKind, f.ResourceNamespace, f.ResourceName)
	}
	if f.Fingerprint == "" {
		t.Error("Fingerprint is empty")
	}
	// CIS/Remediation/VerificationSteps have no OpenReports equivalent —
	// the superset-shape design (plan section C) leaves them empty.
	if f.CIS != nil || f.Remediation != "" || f.VerificationSteps != "" {
		t.Errorf("expected empty CIS/Remediation/VerificationSteps, got %+v", f)
	}
}

func TestOpenReportsIngestor_Ingest_MultiSourceFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/multi_source_clusterreport.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	clusterID := uuid.New()
	batches, err := OpenReportsIngestor{}.Ingest(clusterID, body)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	// Two ReportResults, two distinct per-result Source overrides -> two
	// separate Scan/Batch groups, never merged into one Source.
	if len(batches) != 2 {
		t.Fatalf("len(batches) = %d, want 2", len(batches))
	}

	sources := map[string]int{}
	for _, b := range batches {
		sources[b.Scan.Source] = len(b.Findings)
	}
	if sources["openreports:kyverno"] != 1 {
		t.Errorf("openreports:kyverno findings = %d, want 1", sources["openreports:kyverno"])
	}
	if sources["openreports:trivy-operator"] != 1 {
		t.Errorf("openreports:trivy-operator findings = %d, want 1", sources["openreports:trivy-operator"])
	}
}

func TestOpenReportsIngestor_Ingest_AllPassStillRecordsScan(t *testing.T) {
	body := []byte(`{
		"source": "kyverno",
		"results": [
			{"policy": "require-labels", "result": "pass", "resources": [{"kind": "Pod", "name": "x"}]}
		]
	}`)
	batches, err := OpenReportsIngestor{}.Ingest(uuid.New(), body)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(batches) != 1 {
		t.Fatalf("len(batches) = %d, want 1", len(batches))
	}
	if batches[0].Scan.Source != "openreports:kyverno" {
		t.Errorf("Scan.Source = %q, want openreports:kyverno", batches[0].Scan.Source)
	}
	if len(batches[0].Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(batches[0].Findings))
	}
}

func TestOpenReportsIngestor_Ingest_ResourceSelectorSkipped(t *testing.T) {
	body := []byte(`{
		"source": "kyverno",
		"results": [
			{"policy": "require-labels", "result": "fail", "resourceSelector": {"matchLabels": {"app": "x"}}}
		]
	}`)
	batches, err := OpenReportsIngestor{}.Ingest(uuid.New(), body)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(batches) != 1 || len(batches[0].Findings) != 0 {
		t.Errorf("expected one empty batch for a result with no concrete resources, got %+v", batches)
	}
}

func TestOpenReportsIngestor_Ingest_InvalidJSON(t *testing.T) {
	_, err := OpenReportsIngestor{}.Ingest(uuid.New(), []byte("not json"))
	if err == nil {
		t.Fatal("expected a decode error, got nil")
	}
}

func TestOpenReportsIngestor_Ingest_DeterministicFingerprint(t *testing.T) {
	body := []byte(`{
		"source": "kyverno",
		"results": [
			{"policy": "p", "rule": "r", "result": "fail", "resources": [{"kind": "Pod", "namespace": "ns", "name": "n"}]}
		]
	}`)
	clusterID := uuid.New()
	b1, err := OpenReportsIngestor{}.Ingest(clusterID, body)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	b2, err := OpenReportsIngestor{}.Ingest(clusterID, body)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if b1[0].Findings[0].Fingerprint != b2[0].Findings[0].Fingerprint {
		t.Error("fingerprint is not deterministic for identical input")
	}

	otherCluster, err := OpenReportsIngestor{}.Ingest(uuid.New(), body)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if b1[0].Findings[0].Fingerprint == otherCluster[0].Findings[0].Fingerprint {
		t.Error("fingerprint must differ across clusters (cluster_id is part of the hash input)")
	}
}
