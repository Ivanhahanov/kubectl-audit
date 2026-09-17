package ingest

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

const sampleFindingsJSON = `{
	"generatedAt": "2026-09-01T12:00:00Z",
	"target": "prod-cluster",
	"clusterVersion": "v1.31.2",
	"findings": [
		{
			"id": "abc123",
			"policyId": "no-privileged-containers",
			"title": "Privileged container",
			"severity": "HIGH",
			"category": "workload",
			"cis": ["5.2.1"],
			"resource": {
				"apiVersion": "v1",
				"kind": "Pod",
				"namespace": "default",
				"name": "nginx"
			},
			"message": "container nginx runs privileged",
			"remediation": "set privileged: false",
			"verificationSteps": "check securityContext.privileged"
		}
	]
}`

func TestNativeIngestor_Ingest(t *testing.T) {
	clusterID := uuid.New()
	scan, out, err := NativeIngestor{}.Ingest(clusterID, []byte(sampleFindingsJSON))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	if scan.ClusterID != clusterID {
		t.Errorf("scan.ClusterID = %v, want %v", scan.ClusterID, clusterID)
	}
	if scan.Source != SourceNative {
		t.Errorf("scan.Source = %q, want %q", scan.Source, SourceNative)
	}
	wantGenerated := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	if !scan.GeneratedAt.Equal(wantGenerated) {
		t.Errorf("scan.GeneratedAt = %v, want %v", scan.GeneratedAt, wantGenerated)
	}
	if scan.ClusterVersion != "v1.31.2" {
		t.Errorf("scan.ClusterVersion = %q, want v1.31.2", scan.ClusterVersion)
	}

	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	f := out[0]
	if f.ClusterID != clusterID {
		t.Errorf("f.ClusterID = %v, want %v", f.ClusterID, clusterID)
	}
	if f.Source != SourceNative {
		t.Errorf("f.Source = %q, want %q", f.Source, SourceNative)
	}
	if f.Fingerprint != "abc123" {
		t.Errorf("f.Fingerprint = %q, want abc123", f.Fingerprint)
	}
	if f.PolicyID != "no-privileged-containers" {
		t.Errorf("f.PolicyID = %q", f.PolicyID)
	}
	if f.Severity != "HIGH" {
		t.Errorf("f.Severity = %q, want HIGH", f.Severity)
	}
	if len(f.CIS) != 1 || f.CIS[0] != "5.2.1" {
		t.Errorf("f.CIS = %v, want [5.2.1]", f.CIS)
	}
	if f.ResourceKind != "Pod" || f.ResourceNamespace != "default" || f.ResourceName != "nginx" {
		t.Errorf("f.Resource* = %q/%q/%q, want Pod/default/nginx", f.ResourceKind, f.ResourceNamespace, f.ResourceName)
	}
	if f.Remediation != "set privileged: false" {
		t.Errorf("f.Remediation = %q", f.Remediation)
	}
}

func TestNativeIngestor_Ingest_MissingID(t *testing.T) {
	body := []byte(`{"generatedAt":"2026-09-01T12:00:00Z","findings":[{"policyId":"x","resource":{"kind":"Pod","name":"nginx"}}]}`)
	_, _, err := NativeIngestor{}.Ingest(uuid.New(), body)
	if err == nil {
		t.Fatal("expected an error for a finding with no id, got nil")
	}
}

func TestNativeIngestor_Ingest_EmptyFindings(t *testing.T) {
	body := []byte(`{"generatedAt":"2026-09-01T12:00:00Z","findings":[]}`)
	scan, out, err := NativeIngestor{}.Ingest(uuid.New(), body)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("len(out) = %d, want 0", len(out))
	}
	if scan.Source != SourceNative {
		t.Errorf("scan.Source = %q", scan.Source)
	}
}

func TestNativeIngestor_Ingest_InvalidJSON(t *testing.T) {
	_, _, err := NativeIngestor{}.Ingest(uuid.New(), []byte("not json"))
	if err == nil {
		t.Fatal("expected a decode error, got nil")
	}
}
