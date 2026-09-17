package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlePutAndGetKnowledgeBaseEntry(t *testing.T) {
	srv, _ := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	body := `{"title":"Uses the latest tag","remediation":"Pin a digest.","labels":["supply-chain"]}`
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/knowledge-base/workload.no-latest-tag", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200", resp.StatusCode)
	}

	getReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/knowledge-base/workload.no-latest-tag", nil)
	getReq.Header.Set("Authorization", "Bearer admin-secret")
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", getResp.StatusCode)
	}

	var decoded knowledgeBaseEntryDTO
	if err := json.NewDecoder(getResp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if decoded.Title != "Uses the latest tag" {
		t.Errorf("Title = %q", decoded.Title)
	}
	if decoded.Remediation != "Pin a digest." {
		t.Errorf("Remediation = %q", decoded.Remediation)
	}
	if len(decoded.Labels) != 1 || decoded.Labels[0] != "supply-chain" {
		t.Errorf("Labels = %v", decoded.Labels)
	}
}

func TestHandleGetKnowledgeBaseEntry_NotFound(t *testing.T) {
	srv, _ := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/knowledge-base/no-such-policy", nil)
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

func TestHandleKnowledgeBase_WrongAdminToken(t *testing.T) {
	srv, _ := newTestServer()
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/knowledge-base/x", nil)
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
