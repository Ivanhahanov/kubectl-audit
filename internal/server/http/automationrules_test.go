package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleCreateListPatchDeleteAutomationRule(t *testing.T) {
	srv, _ := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	body := `{"name":"file critical","enabled":true,"trigger":{"minSeverity":"CRITICAL","status":"confirmed"},"action":{"type":"file_jira"}}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/automation-rules", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", resp.StatusCode)
	}
	var created automationRuleDTO
	json.NewDecoder(resp.Body).Decode(&created)
	if created.ID == "" || created.Trigger.MinSeverity != "CRITICAL" {
		t.Fatalf("created = %+v", created)
	}

	listReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/automation-rules", nil)
	listReq.Header.Set("Authorization", "Bearer admin-secret")
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list request failed: %v", err)
	}
	defer listResp.Body.Close()
	var listed struct {
		Rules []automationRuleDTO `json:"rules"`
	}
	json.NewDecoder(listResp.Body).Decode(&listed)
	if len(listed.Rules) != 1 {
		t.Fatalf("Rules = %+v, want 1", listed.Rules)
	}

	patchBody := `{"name":"file critical","enabled":false,"trigger":{"minSeverity":"CRITICAL"},"action":{"type":"file_jira"}}`
	patchReq, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/automation-rules/"+created.ID, bytes.NewReader([]byte(patchBody)))
	patchReq.Header.Set("Authorization", "Bearer admin-secret")
	patchResp, err := http.DefaultClient.Do(patchReq)
	if err != nil {
		t.Fatalf("PATCH request failed: %v", err)
	}
	defer patchResp.Body.Close()
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH status = %d, want 200", patchResp.StatusCode)
	}
	var patched automationRuleDTO
	json.NewDecoder(patchResp.Body).Decode(&patched)
	if patched.Enabled {
		t.Error("expected Enabled = false after PATCH")
	}

	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/automation-rules/"+created.ID, nil)
	delReq.Header.Set("Authorization", "Bearer admin-secret")
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE request failed: %v", err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", delResp.StatusCode)
	}
}

func TestHandleCreateAutomationRule_RequiresActionType(t *testing.T) {
	srv, _ := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/automation-rules", bytes.NewReader([]byte(`{"name":"x"}`)))
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

func TestHandleEvaluateAutomationRules(t *testing.T) {
	srv, _ := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/automation-rules/evaluate", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var decoded struct {
		Results []any `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(decoded.Results) != 0 {
		t.Errorf("Results = %v, want empty (no clusters registered)", decoded.Results)
	}
}
