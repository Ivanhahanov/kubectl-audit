package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

// fakeStore is an in-memory storage.ClusterRepo + storage.FindingRepo used
// only by these handler tests — per the architecture plan's testing
// strategy, HTTP-layer tests stay fast and container-free; the real
// Postgres-backed contract is exercised separately by
// internal/storage/postgres's testcontainer tests.
type fakeStore struct {
	byID     map[uuid.UUID]storage.Cluster
	byToken  map[string]uuid.UUID
	scans    []storage.Scan
	findings map[string][]storage.Finding // keyed by clusterID.String()
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		byID:     map[uuid.UUID]storage.Cluster{},
		byToken:  map[string]uuid.UUID{},
		findings: map[string][]storage.Finding{},
	}
}

func (f *fakeStore) Register(_ context.Context, name, endpoint, owner, tokenHash string) (storage.Cluster, error) {
	for _, c := range f.byID {
		if c.Name == name {
			return storage.Cluster{}, fmt.Errorf("cluster %q already registered", name)
		}
	}
	c := storage.Cluster{
		ID:        uuid.New(),
		Name:      name,
		Endpoint:  endpoint,
		Owner:     owner,
		TokenHash: tokenHash,
		CreatedAt: time.Now(),
	}
	f.byID[c.ID] = c
	f.byToken[tokenHash] = c.ID
	return c, nil
}

func (f *fakeStore) GetByID(_ context.Context, id uuid.UUID) (storage.Cluster, error) {
	c, ok := f.byID[id]
	if !ok {
		return storage.Cluster{}, storage.ErrNotFound
	}
	return c, nil
}

func (f *fakeStore) GetByTokenHash(_ context.Context, tokenHash string) (storage.Cluster, error) {
	id, ok := f.byToken[tokenHash]
	if !ok {
		return storage.Cluster{}, storage.ErrNotFound
	}
	return f.byID[id], nil
}

func (f *fakeStore) ListClusters(_ context.Context) ([]storage.Cluster, error) {
	var out []storage.Cluster
	for _, c := range f.byID {
		out = append(out, c)
	}
	return out, nil
}

func (f *fakeStore) IngestScan(_ context.Context, scan storage.Scan, findings []storage.Finding) (storage.Scan, error) {
	scan.ID = uuid.New()
	scan.IngestedAt = time.Now()
	f.scans = append(f.scans, scan)
	f.findings[scan.ClusterID.String()] = findings
	return scan, nil
}

func (f *fakeStore) GetFinding(_ context.Context, clusterID uuid.UUID, source, fingerprint string) (storage.Finding, error) {
	for _, fd := range f.findings[clusterID.String()] {
		if fd.Source == source && fd.Fingerprint == fingerprint {
			return fd, nil
		}
	}
	return storage.Finding{}, storage.ErrNotFound
}

func (f *fakeStore) ListFindings(_ context.Context, clusterID uuid.UUID, _ storage.FindingFilter) ([]storage.Finding, error) {
	return f.findings[clusterID.String()], nil
}

func (f *fakeStore) ListByResource(context.Context, uuid.UUID, string, string, string) ([]storage.Finding, error) {
	return nil, nil
}

func (f *fakeStore) ListScans(_ context.Context, clusterID uuid.UUID) ([]storage.Scan, error) {
	var out []storage.Scan
	for _, sc := range f.scans {
		if sc.ClusterID == clusterID {
			out = append(out, sc)
		}
	}
	return out, nil
}

func newTestServer() (*Server, *fakeStore) {
	store := newFakeStore()
	return NewServer(store, store, "admin-secret"), store
}

func TestHandleRegisterCluster(t *testing.T) {
	srv, _ := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/clusters", strings.NewReader(`{"name":"prod","owner":"team-x"}`))
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
}

func TestHandleRegisterCluster_WrongAdminToken(t *testing.T) {
	srv, _ := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/clusters", strings.NewReader(`{"name":"prod"}`))
	req.Header.Set("Authorization", "Bearer wrong")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandleIngestNative(t *testing.T) {
	srv, store := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	// Register a cluster directly against the fake store to get a real
	// token without going through the HTTP registration handler twice.
	plaintext, hash, err := newClusterToken()
	if err != nil {
		t.Fatalf("newClusterToken: %v", err)
	}
	cluster, err := store.Register(context.Background(), "prod", "", "", hash)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ingest/native", strings.NewReader(sampleFindingsJSONForTest))
	req.Header.Set("Authorization", "Bearer "+plaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	got := store.findings[cluster.ID.String()]
	if len(got) != 1 {
		t.Fatalf("stored findings = %d, want 1", len(got))
	}
	if got[0].Fingerprint != "abc123" {
		t.Errorf("fingerprint = %q, want abc123", got[0].Fingerprint)
	}

	var decoded ingestResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(decoded.Scans) != 1 || decoded.Scans[0].FindingsIngested != 1 {
		t.Errorf("decoded.Scans = %+v, want one scan with 1 finding", decoded.Scans)
	}
}

func TestHandleIngestOpenReports(t *testing.T) {
	srv, store := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	plaintext, hash, err := newClusterToken()
	if err != nil {
		t.Fatalf("newClusterToken: %v", err)
	}
	cluster, err := store.Register(context.Background(), "or-cluster", "", "", hash)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	body := `{
		"source": "kyverno",
		"results": [
			{"policy": "disallow-privileged", "rule": "privileged", "severity": "high", "result": "fail",
			 "message": "privileged containers are not allowed",
			 "resources": [{"apiVersion": "v1", "kind": "Pod", "namespace": "default", "name": "nginx"}]},
			{"policy": "require-labels", "result": "pass",
			 "resources": [{"kind": "Pod", "namespace": "default", "name": "nginx"}]}
		]
	}`

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ingest/openreports", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+plaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	got := store.findings[cluster.ID.String()]
	if len(got) != 1 {
		t.Fatalf("stored findings = %d, want 1 (the pass result must not be stored)", len(got))
	}
	if got[0].Source != "openreports:kyverno" {
		t.Errorf("Source = %q, want openreports:kyverno", got[0].Source)
	}
	if got[0].Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", got[0].Severity)
	}
}

func TestHandleIngestNative_InvalidToken(t *testing.T) {
	srv, _ := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ingest/native", strings.NewReader(sampleFindingsJSONForTest))
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

const sampleFindingsJSONForTest = `{
	"generatedAt": "2026-09-01T12:00:00Z",
	"findings": [
		{
			"id": "abc123",
			"policyId": "no-privileged-containers",
			"title": "Privileged container",
			"severity": "HIGH",
			"resource": {"kind": "Pod", "namespace": "default", "name": "nginx"},
			"message": "container nginx runs privileged"
		}
	]
}`
