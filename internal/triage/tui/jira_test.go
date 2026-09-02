package tui

import (
	"strings"
	"testing"

	"github.com/rivo/tview"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

// TestJiraPreviewText_NotConfiguredShowsClearMessage guards that a triager
// who presses 'v' before setting up triage.jira gets told why nothing
// showed up, not a blank or misleading preview.
func TestJiraPreviewText_NotConfiguredShowsClearMessage(t *testing.T) {
	a := &app{}
	row := dedupRow("1", "workload.run-as-non-root", "msg", "ns", "app")
	got := a.jiraPreviewText(row)
	if !strings.Contains(got, "not configured") {
		t.Errorf("expected a clear not-configured message, got %q", got)
	}
}

// TestJiraPreviewText_MatchesWhatCreateOneIssueWouldSend is the actual
// WYSIWYG guarantee: the preview must reflect a custom summaryTemplate and
// custom labels/fields exactly, not detailText's fixed layout.
func TestJiraPreviewText_MatchesWhatCreateOneIssueWouldSend(t *testing.T) {
	a := &app{
		jira: JiraConfig{
			BaseURL: "https://jira.example.com", ProjectKey: "SEC", IssueType: "Bug",
			SummaryTemplate: "[custom] {{.Content.Title}}",
			ExtraLabels:     []string{"platform-team"},
			CustomFields:    map[string]any{"customfield_10010": "sev={{.Finding.Severity}}"},
		},
	}
	row := dedupRow("1", "workload.run-as-non-root", "msg", "ns", "app")
	row.Finding.Title = "Container runs as root"
	row.Finding.Severity = findings.SeverityHigh

	got := a.jiraPreviewText(row)
	for _, want := range []string{
		"SEC", "Bug",
		tview.Escape("[custom] Container runs as root"), // custom summary template applied, escaped
		"platform-team", // extraLabels merged in
		"customfield_10010",
		"sev=HIGH", // custom field templated
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected the preview to contain %q, got:\n%s", want, got)
		}
	}
}

// TestJiraPreviewText_EscapesBracketsInRenderedContent guards against the
// exact failure mode a Jira wiki-markup description template invites — a
// literal "[CVE-2024-1234]"-shaped reference in the rendered summary/
// description falls inside tview's own color/region tag character set
// ([a-zA-Z0-9_,;: -."#]) and, unescaped, would be misread as a tag by the
// same TextView that displays it (corrupting the rendered text or
// vanishing silently) rather than shown as the literal reference it is.
func TestJiraPreviewText_EscapesBracketsInRenderedContent(t *testing.T) {
	a := &app{
		jira: JiraConfig{
			BaseURL: "https://jira.example.com", ProjectKey: "SEC", IssueType: "Bug",
			DescriptionTemplate: "Tracked as [CVE-2024-1234], see the security-baseline doc.",
		},
	}
	row := dedupRow("1", "workload.run-as-non-root", "msg", "ns", "app")

	got := a.jiraPreviewText(row)
	raw := "Tracked as [CVE-2024-1234], see the security-baseline doc."
	if strings.Contains(got, raw) {
		t.Errorf("expected the literal bracketed text to be tview-escaped (see tview.Escape), found it unescaped:\n%s", got)
	}
	if !strings.Contains(got, tview.Escape(raw)) {
		t.Errorf("expected the tview.Escape'd form of the description to appear, got:\n%s", got)
	}
}

// TestJiraFilingStatus_NotConfirmedNotesItWontFileYet is a small guardrail
// against a triager assuming 'j' silently worked from the preview screen —
// jiraFilingStatus is what openDetail's 'v' handler flashes into the
// hint/status bar, deliberately kept out of jiraPreviewText's own body
// (see its doc comment): filing status is meta-information about the
// action, not part of the ticket content a triager is reviewing.
func TestJiraFilingStatus_NotConfirmedNotesItWontFileYet(t *testing.T) {
	row := dedupRow("1", "workload.run-as-non-root", "msg", "ns", "app")
	row.Entry.Status = triage.StatusNew

	got := jiraFilingStatus(row)
	if !strings.Contains(got, "CONFIRMED") {
		t.Errorf("expected a note that the finding isn't confirmed yet, got %q", got)
	}
}

// TestJiraFilingStatus_AlreadyFiledNamesTheIssue.
func TestJiraFilingStatus_AlreadyFiledNamesTheIssue(t *testing.T) {
	row := dedupRow("1", "workload.run-as-non-root", "msg", "ns", "app")
	row.Entry.Status = triage.StatusConfirmed
	row.Entry.JiraIssueKey = "SEC-123"
	row.Entry.JiraIssueURL = "https://jira.example.com/browse/SEC-123"

	got := jiraFilingStatus(row)
	if !strings.Contains(got, "SEC-123") {
		t.Errorf("expected the filing status to name the already-filed issue, got %q", got)
	}
}

// TestJiraFilingStatus_ConfirmedAndUnfiledIsEmpty is the "ready to file,
// nothing to warn about" case — jiraFilingStatus must return "" so the 'v'
// handler falls back to the plain "Jira ticket preview" flash instead of
// an empty or confusing note.
func TestJiraFilingStatus_ConfirmedAndUnfiledIsEmpty(t *testing.T) {
	row := dedupRow("1", "workload.run-as-non-root", "msg", "ns", "app")
	row.Entry.Status = triage.StatusConfirmed

	if got := jiraFilingStatus(row); got != "" {
		t.Errorf("expected no filing-status note for a confirmed, not-yet-filed finding, got %q", got)
	}
}

// TestJiraPreviewText_NoFilingStatusInBody guards that jiraPreviewText's
// own body no longer mixes in filing-status meta-info — it belongs in the
// hint/status bar (see jiraFilingStatus), not the scrollable ticket
// content a triager is reviewing.
func TestJiraPreviewText_NoFilingStatusInBody(t *testing.T) {
	a := &app{jira: JiraConfig{BaseURL: "https://jira.example.com", ProjectKey: "SEC", IssueType: "Bug"}}
	row := dedupRow("1", "workload.run-as-non-root", "msg", "ns", "app")
	row.Entry.Status = triage.StatusNew

	got := a.jiraPreviewText(row)
	for _, unwanted := range []string{"Not yet filed", "Already filed", "CONFIRMED"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("expected jiraPreviewText's body to no longer contain filing-status text %q, got:\n%s", unwanted, got)
		}
	}
}
