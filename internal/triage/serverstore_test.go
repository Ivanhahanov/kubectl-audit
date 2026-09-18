package triage

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServerStore_Load_FiltersUntriagedEntries(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want Bearer test-token", got)
		}
		if got := r.URL.Query().Get("source"); got != "kubectl-audit" {
			t.Errorf("source query = %q, want kubectl-audit", got)
		}
		if got := r.URL.Query().Get("cluster_id"); got != "cluster-1" {
			t.Errorf("cluster_id query = %q, want cluster-1", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(serverTriageViewResponse{
			Entries: []serverTriageView{
				{Fingerprint: "untouched", Status: "new"},
				{
					Fingerprint: "abc123", PolicyID: "no-privileged-containers", Title: "Privileged container",
					Resource: serverResourceRef{Kind: "Pod", Namespace: "default", Name: "nginx"},
					Status:   "confirmed", Note: "looks real",
				},
			},
		})
	}))
	defer ts.Close()

	store := ServerStore{BaseURL: ts.URL, Token: "test-token", ClusterID: "cluster-1", Source: "kubectl-audit"}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(state.Entries) != 1 {
		t.Fatalf("len(Entries) = %d, want 1 (untriaged entries must be filtered out)", len(state.Entries))
	}
	e, ok := state.Entries["abc123"]
	if !ok {
		t.Fatal("expected an Entry for abc123")
	}
	if e.Status != StatusConfirmed {
		t.Errorf("Status = %q, want confirmed", e.Status)
	}
	if e.Note != "looks real" {
		t.Errorf("Note = %q", e.Note)
	}
	if e.Resource.Kind != "Pod" || e.Resource.Name != "nginx" {
		t.Errorf("Resource = %+v, want Pod/nginx", e.Resource)
	}
}

func TestServerStore_Load_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid token"}`))
	}))
	defer ts.Close()

	store := ServerStore{BaseURL: ts.URL, Token: "bad-token", Source: "kubectl-audit"}
	if _, err := store.Load(); err == nil {
		t.Fatal("expected an error for a 401 response, got nil")
	}
}

func TestServerStore_Save_SendsBulkRequest(t *testing.T) {
	var captured bulkTriageRequestDTO
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/triage/bulk" {
			t.Errorf("path = %q, want /api/v1/triage/bulk", r.URL.Path)
		}
		if got := r.URL.Query().Get("cluster_id"); got != "cluster-1" {
			t.Errorf("cluster_id query = %q, want cluster-1", got)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"updated": len(captured.Entries)})
	}))
	defer ts.Close()

	store := ServerStore{BaseURL: ts.URL, Token: "test-token", ClusterID: "cluster-1", Source: "kubectl-audit"}
	state := &State{Entries: map[string]Entry{
		"abc123": {FindingID: "abc123", Status: StatusConfirmed, Note: "looks real"},
	}}
	if err := store.Save(state); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if captured.Source != "kubectl-audit" {
		t.Errorf("Source = %q, want kubectl-audit", captured.Source)
	}
	if len(captured.Entries) != 1 || captured.Entries[0].Fingerprint != "abc123" {
		t.Errorf("Entries = %+v, want one entry for abc123", captured.Entries)
	}
	if captured.Entries[0].Status != "confirmed" {
		t.Errorf("Status = %q, want confirmed", captured.Entries[0].Status)
	}
}

func TestServerStore_Save_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	store := ServerStore{BaseURL: ts.URL, Token: "test-token", Source: "kubectl-audit"}
	state := &State{Entries: map[string]Entry{}}
	if err := store.Save(state); err == nil {
		t.Fatal("expected an error for a 500 response, got nil")
	}
}

func TestServerStore_Label(t *testing.T) {
	store := ServerStore{BaseURL: "https://audit.example.com", Source: "kubectl-audit"}
	want := "https://audit.example.com (server, source=kubectl-audit)"
	if got := store.Label(); got != want {
		t.Errorf("Label() = %q, want %q", got, want)
	}
}
