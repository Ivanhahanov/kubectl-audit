package triage_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
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

// allAutoLabels is the "everything on" AutoLabels value most tests that
// aren't specifically about the per-label toggles want.
var allAutoLabels = triage.AutoLabels{Tool: true, Severity: true, Category: true}

func TestIssueLabels_SanitizesSeverityAndCategory(t *testing.T) {
	f := mustFinding("f1")
	f.Severity = "HIGH"
	f.Category = "workload security" // space, needs sanitizing

	labels := triage.IssueLabels(f, nil, allAutoLabels, nil)
	want := map[string]bool{"kubectl-audit": true, "high": true, "workload-security": true}
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

	labels := triage.IssueLabels(f, nil, allAutoLabels, []string{"Team-Sec", "high"}) // "high" duplicates the severity label
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

// TestIssueLabels_IncludesKnowledgeBaseLabels is the fix for a real need:
// an org-defined per-check label (e.g. an internal compliance requirement
// id like "k-ose-5") that's the same for every finding a check produces.
func TestIssueLabels_IncludesKnowledgeBaseLabels(t *testing.T) {
	f := mustFinding("f1")
	kb := map[string]findings.KnowledgeBaseEntry{f.PolicyID: {Labels: []string{"k-ose-5", "K-OSE-5"}}}

	labels := triage.IssueLabels(f, kb, allAutoLabels, nil)
	count := 0
	for _, l := range labels {
		if l == "k-ose-5" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected the knowledge-base label present exactly once (sanitized+deduped even though the source had a case-only duplicate), got labels %v", labels)
	}
}

// TestIssueLabels_AutoLabelsAreIndependentPerField is the fix for a real
// request: a Jira project that already tracks severity in its own
// dedicated field shouldn't also get it duplicated as a label — but should
// keep the "kubectl-audit" and category ones. Each of AutoLabels' three
// fields must be controllable independently, not just an all-or-nothing
// switch.
func TestIssueLabels_AutoLabelsAreIndependentPerField(t *testing.T) {
	f := mustFinding("f1")
	f.Severity = "critical"
	f.Category = "workload-security"

	labels := triage.IssueLabels(f, nil, triage.AutoLabels{Tool: true, Severity: false, Category: true}, nil)

	has := map[string]bool{}
	for _, l := range labels {
		has[l] = true
	}
	if !has["kubectl-audit"] {
		t.Error("expected the tool label to survive (Tool: true)")
	}
	if has["critical"] {
		t.Error("expected the severity label to be suppressed (Severity: false)")
	}
	if !has["workload-security"] {
		t.Error("expected the category label to survive (Category: true)")
	}
}

// TestIssueLabels_AllAutoLabelsOffLeavesOnlyOrgDefinedOnes guards the fully
// suppressed case: with every AutoLabels field false, only kb Labels and
// extra survive — none of this tool's own automatic ones.
func TestIssueLabels_AllAutoLabelsOffLeavesOnlyOrgDefinedOnes(t *testing.T) {
	f := mustFinding("f1")
	f.Severity = "critical"
	f.Category = "workload-security"
	kb := map[string]findings.KnowledgeBaseEntry{f.PolicyID: {Labels: []string{"k-ose-5"}}}

	labels := triage.IssueLabels(f, kb, triage.AutoLabels{}, []string{"team-sec"})

	want := map[string]bool{"k-ose-5": true, "team-sec": true}
	if len(labels) != len(want) {
		t.Fatalf("expected only the org-defined labels, got %v", labels)
	}
	for _, l := range labels {
		if !want[l] {
			t.Errorf("unexpected label %q with every AutoLabels field false", l)
		}
	}
}

func TestRenderIssueSummary_EmptyTemplateUsesDefault(t *testing.T) {
	f := mustFinding("f1")
	summary, err := triage.RenderIssueSummary(f, nil, triage.Entry{}, "")
	if err != nil {
		t.Fatalf("RenderIssueSummary: %v", err)
	}
	if !strings.Contains(summary, string(f.Severity)) || !strings.Contains(summary, f.Title) {
		t.Errorf("expected the default summary to mention severity and title, got %q", summary)
	}
}

func TestRenderIssueSummary_KnowledgeBaseOverridesTitle(t *testing.T) {
	f := mustFinding("f1")
	kb := map[string]findings.KnowledgeBaseEntry{f.PolicyID: {Title: "Наш заголовок"}}
	summary, err := triage.RenderIssueSummary(f, kb, triage.Entry{}, "")
	if err != nil {
		t.Fatalf("RenderIssueSummary: %v", err)
	}
	if !strings.Contains(summary, "Наш заголовок") {
		t.Errorf("expected the knowledge-base title to appear in the summary, got %q", summary)
	}
}

func TestRenderIssueSummary_CustomTemplateOverrides(t *testing.T) {
	f := mustFinding("f1")
	summary, err := triage.RenderIssueSummary(f, nil, triage.Entry{}, "Найдено: {{.Content.Title}}")
	if err != nil {
		t.Fatalf("RenderIssueSummary: %v", err)
	}
	if summary != "Найдено: "+f.Title {
		t.Errorf("expected the custom template to fully replace the default, got %q", summary)
	}
}

func TestRenderIssueDescription_EmbedsBackLink(t *testing.T) {
	f := mustFinding("f1")
	f.Remediation = "fix it"
	desc, err := triage.RenderIssueDescription(f, nil, triage.Entry{Note: "looks real"}, "")
	if err != nil {
		t.Fatalf("RenderIssueDescription: %v", err)
	}

	for _, want := range []string{"kubectl-audit finding: f1", "fix it", "looks real"} {
		if !strings.Contains(desc, want) {
			t.Errorf("expected description to contain %q, got:\n%s", want, desc)
		}
	}
	if strings.Contains(desc, "Verification") {
		t.Errorf("expected no verification-steps section in the ticket description, got:\n%s", desc)
	}
}

// TestRenderIssueDescription_KnowledgeBaseShowsTechnicalDetail is the
// "don't silently hide the tool's own precise detail behind an org
// explanation" guarantee — see triage.ResolvedContent.Technical.
func TestRenderIssueDescription_KnowledgeBaseShowsTechnicalDetail(t *testing.T) {
	f := mustFinding("f1")
	f.Message = "ServiceAccount x can do y"
	kb := map[string]findings.KnowledgeBaseEntry{f.PolicyID: {Description: "Наше объяснение уязвимости."}}
	desc, err := triage.RenderIssueDescription(f, kb, triage.Entry{}, "")
	if err != nil {
		t.Fatalf("RenderIssueDescription: %v", err)
	}
	if !strings.Contains(desc, "Наше объяснение уязвимости.") {
		t.Errorf("expected the knowledge-base description, got:\n%s", desc)
	}
	if !strings.Contains(desc, "ServiceAccount x can do y") {
		t.Errorf("expected the original technical message to still appear, got:\n%s", desc)
	}
}

func TestRenderIssueDescription_CustomTemplateOverrides(t *testing.T) {
	f := mustFinding("f1")
	desc, err := triage.RenderIssueDescription(f, nil, triage.Entry{}, "Сообщение: {{.Content.Description}}")
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
	}, f, nil, triage.Entry{}, "")
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
	out, err := triage.RenderCustomFields(nil, mustFinding("f1"), nil, triage.Entry{}, "")
	if err != nil {
		t.Fatalf("RenderCustomFields: %v", err)
	}
	if out != nil {
		t.Errorf("expected nil for an empty/nil customFields map and no owner, got %v", out)
	}
}

// TestRenderCustomFields_OwnerBecomesAssignee is the fix for a real
// request: output.owner (the "who's responsible" field also shown in the
// Markdown/Confluence report header) should drive who a filed Jira ticket
// gets assigned to, not just be report decoration.
func TestRenderCustomFields_OwnerBecomesAssignee(t *testing.T) {
	out, err := triage.RenderCustomFields(nil, mustFinding("f1"), nil, triage.Entry{}, "jsmith")
	if err != nil {
		t.Fatalf("RenderCustomFields: %v", err)
	}
	assignee, ok := out["assignee"]
	if !ok {
		t.Fatalf("expected an assignee field derived from owner, got %v", out)
	}
	data, err := json.Marshal(assignee)
	if err != nil {
		t.Fatalf("marshaling assignee: %v", err)
	}
	if string(data) != `{"name":"jsmith"}` {
		t.Errorf("expected the Jira Server/DC assignee shape {\"name\":\"jsmith\"}, got %s", data)
	}
}

// TestRenderCustomFields_ExplicitAssigneeWinsOverOwner guards that an
// explicit customFields.assignee (a deliberate per-project override) is
// never clobbered by the owner-derived default.
func TestRenderCustomFields_ExplicitAssigneeWinsOverOwner(t *testing.T) {
	out, err := triage.RenderCustomFields(map[string]any{
		"assignee": map[string]any{"name": "explicit-user"},
	}, mustFinding("f1"), nil, triage.Entry{}, "jsmith")
	if err != nil {
		t.Fatalf("RenderCustomFields: %v", err)
	}
	obj, ok := out["assignee"].(map[string]any)
	if !ok || obj["name"] != "explicit-user" {
		t.Errorf("expected the explicit customFields.assignee to win over owner, got %v", out["assignee"])
	}
}
