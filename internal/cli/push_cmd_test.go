package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPushCmd_SendsFindingsWithBearerToken(t *testing.T) {
	var gotAuth, gotBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		if r.URL.Path != "/api/v1/ingest/native" {
			t.Errorf("path = %q, want /api/v1/ingest/native", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"scans":[{"scanId":"x","source":"kubectl-audit","findingsIngested":1}]}`))
	}))
	defer ts.Close()

	dir := t.TempDir()
	findingsPath := filepath.Join(dir, "findings.json")
	const findingsBody = `{"generatedAt":"2026-09-01T12:00:00Z","findings":[]}`
	if err := os.WriteFile(findingsPath, []byte(findingsBody), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	cmd := newPushCmd()
	cmd.SetArgs([]string{"--server", ts.URL, "--token", "test-token", "--findings", findingsPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q, want Bearer test-token", gotAuth)
	}
	if gotBody != findingsBody {
		t.Errorf("body = %q, want %q", gotBody, findingsBody)
	}
}

func TestPushCmd_ServerRejection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid token"}`))
	}))
	defer ts.Close()

	dir := t.TempDir()
	findingsPath := filepath.Join(dir, "findings.json")
	os.WriteFile(findingsPath, []byte(`{"findings":[]}`), 0o644)

	cmd := newPushCmd()
	cmd.SetArgs([]string{"--server", ts.URL, "--token", "bad-token", "--findings", findingsPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a 401 response, got nil")
	}
}

func TestPushCmd_RequiresServerAndToken(t *testing.T) {
	t.Setenv("KUBECTL_AUDIT_SERVER_URL", "")
	t.Setenv("KUBECTL_AUDIT_SERVER_TOKEN", "")
	cmd := newPushCmd()
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when neither --server nor $KUBECTL_AUDIT_SERVER_URL is set")
	}
}
