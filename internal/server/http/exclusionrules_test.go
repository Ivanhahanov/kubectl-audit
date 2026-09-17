package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleCreateAndListExclusionRules(t *testing.T) {
	srv, _ := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	body := `{"policyIds":["workload.no-latest-tag"],"match":{"kind":"Deployment","namespace":"kube-system"},"reason":"known false positive"}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/exclusion-rules", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", resp.StatusCode)
	}
	var created exclusionRuleDTO
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if created.ID == "" {
		t.Error("expected a generated ID")
	}
	if created.Match.Kind != "Deployment" {
		t.Errorf("Match.Kind = %q", created.Match.Kind)
	}

	listReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/exclusion-rules", nil)
	listReq.Header.Set("Authorization", "Bearer admin-secret")
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer listResp.Body.Close()
	var decoded struct {
		Rules []exclusionRuleDTO `json:"rules"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(decoded.Rules) != 1 || decoded.Rules[0].ID != created.ID {
		t.Errorf("Rules = %+v, want one rule matching %+v", decoded.Rules, created)
	}
}

func TestHandleCreateExclusionRule_RequiresReason(t *testing.T) {
	srv, _ := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/exclusion-rules", bytes.NewReader([]byte(`{"match":{"kind":"Pod"}}`)))
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

func TestHandleDeleteExclusionRule(t *testing.T) {
	srv, _ := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	createReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/exclusion-rules", bytes.NewReader([]byte(`{"reason":"temp"}`)))
	createReq.Header.Set("Authorization", "Bearer admin-secret")
	createResp, err := http.DefaultClient.Do(createReq)
	if err != nil {
		t.Fatalf("create request failed: %v", err)
	}
	var created exclusionRuleDTO
	json.NewDecoder(createResp.Body).Decode(&created)
	createResp.Body.Close()

	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/exclusion-rules/"+created.ID, nil)
	delReq.Header.Set("Authorization", "Bearer admin-secret")
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete request failed: %v", err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", delResp.StatusCode)
	}

	// Deleting again must 404 — the rule is gone.
	delReq2, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/exclusion-rules/"+created.ID, nil)
	delReq2.Header.Set("Authorization", "Bearer admin-secret")
	delResp2, err := http.DefaultClient.Do(delReq2)
	if err != nil {
		t.Fatalf("second delete request failed: %v", err)
	}
	defer delResp2.Body.Close()
	if delResp2.StatusCode != http.StatusNotFound {
		t.Fatalf("second delete status = %d, want 404", delResp2.StatusCode)
	}
}
