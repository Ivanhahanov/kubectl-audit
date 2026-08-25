package triage_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

func TestJiraClient_CreateIssue_RequestShape(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decoding request body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"10001","key":"SEC-42","self":"http://example/rest/api/2/issue/10001"}`))
	}))
	defer srv.Close()

	client := triage.JiraClient{BaseURL: srv.URL, Token: "sekrit-pat", ProjectKey: "SEC", IssueType: "Bug"}
	key, url, err := client.CreateIssue(context.Background(), "summary text", "description text", []string{"kubectl-audit", "high"}, nil)
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("expected POST, got %s", gotMethod)
	}
	if gotPath != "/rest/api/2/issue" {
		t.Errorf("expected /rest/api/2/issue (REST v2, not Cloud's v3), got %s", gotPath)
	}
	if gotAuth != "Bearer sekrit-pat" {
		t.Errorf("expected Bearer PAT auth, got %q", gotAuth)
	}
	fields, _ := gotBody["fields"].(map[string]any)
	if fields == nil {
		t.Fatalf("expected a fields object in the request body, got %v", gotBody)
	}
	if proj, _ := fields["project"].(map[string]any); proj["key"] != "SEC" {
		t.Errorf("expected project.key=SEC, got %v", fields["project"])
	}
	if it, _ := fields["issuetype"].(map[string]any); it["name"] != "Bug" {
		t.Errorf("expected issuetype.name=Bug, got %v", fields["issuetype"])
	}
	if fields["summary"] != "summary text" {
		t.Errorf("expected summary to round-trip, got %v", fields["summary"])
	}

	if key != "SEC-42" {
		t.Errorf("expected key SEC-42, got %q", key)
	}
	wantURL := srv.URL + "/browse/SEC-42"
	if url != wantURL {
		t.Errorf("expected browse URL %q, got %q", wantURL, url)
	}
}

func TestJiraClient_CreateIssue_CustomFieldsMergeIntoFields(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"1","key":"SEC-1","self":"http://example/rest/api/2/issue/1"}`))
	}))
	defer srv.Close()

	client := triage.JiraClient{BaseURL: srv.URL, Token: "t", ProjectKey: "SEC", IssueType: "Bug"}
	customFields := map[string]any{
		"customfield_10010": "Platform Team",
		"customfield_10020": map[string]any{"value": "Prod"},
	}
	if _, _, err := client.CreateIssue(context.Background(), "s", "d", nil, customFields); err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}

	fields, _ := gotBody["fields"].(map[string]any)
	if fields["customfield_10010"] != "Platform Team" {
		t.Errorf("expected string custom field to pass through, got %v", fields["customfield_10010"])
	}
	obj, _ := fields["customfield_10020"].(map[string]any)
	if obj["value"] != "Prod" {
		t.Errorf("expected object-shaped custom field to pass through unchanged, got %v", fields["customfield_10020"])
	}
}

func TestJiraClient_CreateIssue_NonCreatedStatusErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"errorMessages":["not authorized"]}`))
	}))
	defer srv.Close()

	client := triage.JiraClient{BaseURL: srv.URL, Token: "bad-token", ProjectKey: "SEC", IssueType: "Bug"}
	if _, _, err := client.CreateIssue(context.Background(), "s", "d", nil, nil); err == nil {
		t.Error("expected an error for a non-201 response")
	}
}

func TestIssueLabels_SanitizesTagsAndSeverity(t *testing.T) {
	f := mustFinding("f1")
	f.Severity = "HIGH"
	f.Category = "workload security" // space, needs sanitizing
	e := triage.Entry{Tags: []string{"Internet Facing!", "prod"}}

	labels := triage.IssueLabels(f, e, nil)
	want := map[string]bool{"kubectl-audit": true, "high": true, "workload-security": true, "internet-facing": true, "prod": true}
	if len(labels) != len(want) {
		t.Fatalf("expected %d labels, got %v", len(want), labels)
	}
	for _, l := range labels {
		if !want[l] {
			t.Errorf("unexpected label %q", l)
		}
		if l != "" && strings.Contains(l, " ") {
			t.Errorf("label %q contains whitespace, which Jira rejects", l)
		}
	}
}

func TestIssueLabels_ExtraLabelsMergeAndDedup(t *testing.T) {
	f := mustFinding("f1")
	f.Severity = "high"
	e := triage.Entry{}

	labels := triage.IssueLabels(f, e, []string{"Team-Sec", "high"}) // "high" duplicates the severity label
	count := map[string]int{}
	for _, l := range labels {
		count[l]++
	}
	if count["team-sec"] != 1 {
		t.Errorf("expected the extra label to be sanitized and present once, got labels %v", labels)
	}
	if count["high"] != 1 {
		t.Errorf("expected the duplicate 'high' (from severity + extra) to be deduped, got labels %v", labels)
	}
}

func TestRenderIssueSummary_EmptyTemplateUsesDefault(t *testing.T) {
	f := mustFinding("f1")
	summary, err := triage.RenderIssueSummary(f, triage.Entry{}, "")
	if err != nil {
		t.Fatalf("RenderIssueSummary: %v", err)
	}
	if !strings.Contains(summary, string(f.Severity)) || !strings.Contains(summary, f.Title) {
		t.Errorf("expected the default summary to mention severity and title, got %q", summary)
	}
}

func TestRenderIssueSummary_CustomTemplateOverrides(t *testing.T) {
	f := mustFinding("f1")
	summary, err := triage.RenderIssueSummary(f, triage.Entry{}, "Найдено: {{.Finding.Title}}")
	if err != nil {
		t.Fatalf("RenderIssueSummary: %v", err)
	}
	if summary != "Найдено: "+f.Title {
		t.Errorf("expected the custom template to fully replace the default, got %q", summary)
	}
}

func TestRenderIssueDescription_EmbedsBackLinkAndVerificationSteps(t *testing.T) {
	f := mustFinding("f1")
	f.VerificationSteps = "1. check this 2. check that"
	f.Remediation = "fix it"
	desc, err := triage.RenderIssueDescription(f, triage.Entry{Note: "looks real"}, "")
	if err != nil {
		t.Fatalf("RenderIssueDescription: %v", err)
	}

	for _, want := range []string{"kubectl-audit finding: f1", "check this", "fix it", "looks real"} {
		if !strings.Contains(desc, want) {
			t.Errorf("expected description to contain %q, got:\n%s", want, desc)
		}
	}
}

func TestRenderIssueDescription_CustomTemplateOverrides(t *testing.T) {
	f := mustFinding("f1")
	desc, err := triage.RenderIssueDescription(f, triage.Entry{}, "Сообщение: {{.Finding.Message}}")
	if err != nil {
		t.Fatalf("RenderIssueDescription: %v", err)
	}
	if desc != "Сообщение: "+f.Message {
		t.Errorf("expected the custom template to fully replace the default, got %q", desc)
	}
}

func TestRenderCustomFields(t *testing.T) {
	f := mustFinding("f1")
	f.Severity = "HIGH"

	out, err := triage.RenderCustomFields(map[string]any{
		"customfield_10010": "severity is {{.Finding.Severity}}",
		"customfield_10020": map[string]any{"value": "Prod"},
		"customfield_10030": float64(42),
	}, f, triage.Entry{})
	if err != nil {
		t.Fatalf("RenderCustomFields: %v", err)
	}
	if out["customfield_10010"] != "severity is HIGH" {
		t.Errorf("expected the string value to be templated, got %v", out["customfield_10010"])
	}
	if obj, ok := out["customfield_10020"].(map[string]any); !ok || obj["value"] != "Prod" {
		t.Errorf("expected the object value to pass through unchanged, got %v", out["customfield_10020"])
	}
	if out["customfield_10030"] != float64(42) {
		t.Errorf("expected the numeric value to pass through unchanged, got %v", out["customfield_10030"])
	}
}

func TestRenderCustomFields_EmptyMapReturnsNil(t *testing.T) {
	out, err := triage.RenderCustomFields(nil, mustFinding("f1"), triage.Entry{})
	if err != nil {
		t.Fatalf("RenderCustomFields: %v", err)
	}
	if out != nil {
		t.Errorf("expected nil for an empty/nil customFields map, got %v", out)
	}
}
