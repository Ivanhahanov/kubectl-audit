package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleCreateListAuditRequests(t *testing.T) {
	srv, store := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	cluster, err := store.Register(context.Background(), "audit-target", "", "", "hash-audit")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	body := `{"clusterId":"` + cluster.ID.String() + `","reason":"quarterly compliance check","requestedBy":"alice"}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/audit-requests", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", resp.StatusCode)
	}
	var created auditRequestDTO
	json.NewDecoder(resp.Body).Decode(&created)
	if created.Status != "pending" {
		t.Errorf("Status = %q, want pending", created.Status)
	}

	listReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/audit-requests?cluster_id="+cluster.ID.String(), nil)
	listReq.Header.Set("Authorization", "Bearer admin-secret")
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list request failed: %v", err)
	}
	defer listResp.Body.Close()
	var listed struct {
		Requests []auditRequestDTO `json:"requests"`
	}
	json.NewDecoder(listResp.Body).Decode(&listed)
	if len(listed.Requests) != 1 || listed.Requests[0].ID != created.ID {
		t.Errorf("Requests = %+v", listed.Requests)
	}
}

func TestHandlePatchAuditRequest_ApproveTriggersScan(t *testing.T) {
	srv, store := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	cluster, err := store.Register(context.Background(), "audit-target-2", "", "", "hash-audit-2")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	createBody := `{"clusterId":"` + cluster.ID.String() + `","reason":"ad-hoc check"}`
	createReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/audit-requests", bytes.NewReader([]byte(createBody)))
	createReq.Header.Set("Authorization", "Bearer admin-secret")
	createResp, err := http.DefaultClient.Do(createReq)
	if err != nil {
		t.Fatalf("create request failed: %v", err)
	}
	var created auditRequestDTO
	json.NewDecoder(createResp.Body).Decode(&created)
	createResp.Body.Close()

	patchReq, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/audit-requests/"+created.ID, bytes.NewReader([]byte(`{"status":"approved"}`)))
	patchReq.Header.Set("Authorization", "Bearer admin-secret")
	patchResp, err := http.DefaultClient.Do(patchReq)
	if err != nil {
		t.Fatalf("patch request failed: %v", err)
	}
	defer patchResp.Body.Close()
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", patchResp.StatusCode)
	}
	var patched auditRequestDTO
	json.NewDecoder(patchResp.Body).Decode(&patched)
	// approving with the (default, in tests) LogTrigger configured should
	// have immediately advanced status to "running" and recorded a
	// (logged, non-real) pipeline run name.
	if patched.Status != "running" {
		t.Errorf("Status = %q, want running (LogTrigger should have fired)", patched.Status)
	}
	if patched.TektonPipelineRunName == "" {
		t.Error("expected a TektonPipelineRunName to be recorded")
	}
}

func TestHandleCreateAuditRequest_RequiresReason(t *testing.T) {
	srv, store := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()
	cluster, _ := store.Register(context.Background(), "c", "", "", "h")

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/audit-requests", bytes.NewReader([]byte(`{"clusterId":"`+cluster.ID.String()+`"}`)))
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
