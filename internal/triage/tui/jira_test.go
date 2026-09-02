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

// TestJiraPreviewText_NotConfirmedNotesItWontFileYet is a small guardrail
// against a triager assuming 'j' silently worked from the preview screen.
func TestJiraPreviewText_NotConfirmedNotesItWontFileYet(t *testing.T) {
	a := &app{jira: JiraConfig{BaseURL: "https://jira.example.com", ProjectKey: "SEC", IssueType: "Bug"}}
	row := dedupRow("1", "workload.run-as-non-root", "msg", "ns", "app")
	row.Entry.Status = triage.StatusNew

	got := a.jiraPreviewText(row)
	if !strings.Contains(got, "CONFIRMED") {
		t.Errorf("expected a note that the finding isn't confirmed yet, got:\n%s", got)
	}
}
