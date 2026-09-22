package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

func registerAndIngest(t *testing.T, store *fakeStore, ts *httptest.Server) (cluster storage.Cluster, token string) {
	t.Helper()
	plaintext, hash, err := newClusterToken()
	if err != nil {
		t.Fatalf("newClusterToken: %v", err)
	}
	cluster, err = store.Register(context.Background(), "triage-cluster", "", "", hash)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ingest/native", bytes.NewReader([]byte(sampleFindingsJSONForTest)))
	req.Header.Set("Authorization", "Bearer "+plaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("seeding ingest: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seeding ingest status = %d, want 200", resp.StatusCode)
	}
	return cluster, plaintext
}

func TestHandleGetTriage_DefaultsToNewForUntriaged(t *testing.T) {
	srv, store := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	cluster, _ := registerAndIngest(t, store, ts)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/triage?cluster_id="+cluster.ID.String()+"&source=kubectl-audit", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var decoded triageViewResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(decoded.Entries) != 1 {
		t.Fatalf("len(Entries) = %d, want 1", len(decoded.Entries))
	}
	e := decoded.Entries[0]
	if e.Fingerprint != "abc123" {
		t.Errorf("Fingerprint = %q, want abc123", e.Fingerprint)
	}
	if e.Status != string(storage.TriageStatusNew) {
		t.Errorf("Status = %q, want new (untriaged default)", e.Status)
	}
	if e.Resource.Kind != "Pod" || e.Resource.Name != "nginx" {
		t.Errorf("Resource = %+v, want Pod/nginx", e.Resource)
	}
}

func TestHandlePatchTriageEntry(t *testing.T) {
	srv, store := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	cluster, _ := registerAndIngest(t, store, ts)

	body := `{"status":"confirmed","note":"looks real"}`
	req, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/triage/kubectl-audit/abc123?cluster_id="+cluster.ID.String(), bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// A second PATCH that only sets a reviewer must not wipe out the note
	// or status set by the first PATCH — the whole point of partial-update
	// semantics.
	body2 := `{"reviewer":"alice"}`
	req2, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/triage/kubectl-audit/abc123?cluster_id="+cluster.ID.String(), bytes.NewReader([]byte(body2)))
	req2.Header.Set("Authorization", "Bearer admin-secret")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp2.StatusCode)
	}

	var entry storage.TriageEntry
	if err := json.NewDecoder(resp2.Body).Decode(&entry); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if entry.Status != storage.TriageStatusConfirmed {
		t.Errorf("Status = %q, want confirmed (must survive the second PATCH)", entry.Status)
	}
	if entry.Note != "looks real" {
		t.Errorf("Note = %q, want %q (must survive the second PATCH)", entry.Note, "looks real")
	}
	if entry.Reviewer != "alice" {
		t.Errorf("Reviewer = %q, want alice", entry.Reviewer)
	}
}

func TestHandlePatchTriageEntry_UnknownFinding(t *testing.T) {
	srv, store := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	cluster, _ := registerAndIngest(t, store, ts)

	req, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/triage/kubectl-audit/does-not-exist?cluster_id="+cluster.ID.String(), bytes.NewReader([]byte(`{"status":"confirmed"}`)))
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandleBulkTriageUpdate(t *testing.T) {
	srv, store := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	cluster, _ := registerAndIngest(t, store, ts)

	body := `{"source":"kubectl-audit","entries":[
		{"fingerprint":"abc123","status":"wont_fix","note":"accepted risk"},
		{"fingerprint":"ghost-finding","status":"confirmed"}
	]}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/triage/bulk?cluster_id="+cluster.ID.String(), bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var decoded bulkTriageResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if decoded.Updated != 1 {
		t.Errorf("Updated = %d, want 1", decoded.Updated)
	}
	if len(decoded.Skipped) != 1 || decoded.Skipped[0].Fingerprint != "ghost-finding" {
		t.Errorf("Skipped = %+v, want one entry for ghost-finding", decoded.Skipped)
	}
}

// TestHandleGetTriage_ScopedByClusterID replaces the old cross-cluster
// *token* isolation test — triage reads are no longer scoped by which
// cluster's token the caller presents (see handleGetTriage's doc comment):
// an admin caller names the cluster explicitly via cluster_id, and this
// checks that naming cluster B's id genuinely returns only cluster B's
// (empty) findings, not cluster A's.
func TestHandleGetTriage_ScopedByClusterID(t *testing.T) {
	srv, store := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	clusterA, _ := registerAndIngest(t, store, ts)

	_, hashB, err := newClusterToken()
	if err != nil {
		t.Fatalf("newClusterToken: %v", err)
	}
	clusterB, err := store.Register(context.Background(), "other-cluster", "", "", hashB)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/triage?cluster_id="+clusterB.ID.String(), nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var decoded triageViewResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(decoded.Entries) != 0 {
		t.Errorf("cluster_id=%s saw %d entries, want 0 (cluster A's findings must not leak)", clusterB.ID, len(decoded.Entries))
	}

	reqA, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/triage?cluster_id="+clusterA.ID.String(), nil)
	reqA.Header.Set("Authorization", "Bearer admin-secret")
	respA, err := http.DefaultClient.Do(reqA)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer respA.Body.Close()

	var decodedA triageViewResponse
	if err := json.NewDecoder(respA.Body).Decode(&decodedA); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(decodedA.Entries) != 1 {
		t.Errorf("cluster_id=%s saw %d entries, want 1", clusterA.ID, len(decodedA.Entries))
	}
}

// TestHandleGetTriage_RejectsClusterPushToken is the core invariant behind
// this endpoint moving off clusterFromToken: a cluster's own ingest token
// must not double as read access to its findings/triage — that's an
// "expert" action, gated by the admin token instead (see NewServer's doc
// comment on the admin/cluster token split).
func TestHandleGetTriage_RejectsClusterPushToken(t *testing.T) {
	srv, store := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	cluster, token := registerAndIngest(t, store, ts)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/triage?cluster_id="+cluster.ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (a cluster's push token must not grant triage read access)", resp.StatusCode)
	}
}
