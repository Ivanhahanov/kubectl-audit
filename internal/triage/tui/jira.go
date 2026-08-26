package tui

import (
	"context"
	"fmt"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

// JiraConfig is the subset of Jira connection details the 'j' hotkey needs
// — resolved by the caller (internal/cli/triage_cmd.go) exactly the way
// `triage jira-sync` already resolves it (audit.yaml, then --jira-url/
// --project/--issue-type/--jira-token or $KUBECTL_AUDIT_JIRA_TOKEN). A
// zero-value Config here just means the 'j' action reports "not
// configured" instead of doing anything.
type JiraConfig struct {
	BaseURL    string
	Token      string
	ProjectKey string
	IssueType  string
	// SummaryTemplate/DescriptionTemplate are already-loaded Go template
	// source (from triage.jira.summaryTemplate/descriptionTemplate — see
	// internal/cli/triage_cmd.go's resolveJiraConfig, which reads the
	// configured file path). Empty uses triage.RenderIssueSummary/
	// RenderIssueDescription's embedded default.
	SummaryTemplate     string
	DescriptionTemplate string
	// ExtraLabels are static labels (triage.jira.extraLabels) added to
	// every created issue beyond IssueLabels' auto-derived ones.
	ExtraLabels []string
	// CustomFields (triage.jira.customFields) are merged into every
	// created issue's fields — see triage.RenderCustomFields.
	CustomFields map[string]any
}

func (c JiraConfig) configured() bool {
	return c.BaseURL != "" && c.ProjectKey != "" && c.IssueType != ""
}

// createOneIssue renders r's summary/description/labels/customFields
// (per a.jira's configured templates/extras) and creates the Jira issue,
// returning its key/URL. Factored out of createJiraIssues purely so the
// per-target render-then-create sequence reads as one straight-line list
// of steps instead of a nested error-check chain.
func (a *app) createOneIssue(ctx context.Context, client triage.JiraClient, r triage.Row) (key, url string, err error) {
	f := *r.Finding
	summary, err := triage.RenderIssueSummary(f, a.knowledgeBase, r.Entry, a.jira.SummaryTemplate)
	if err != nil {
		return "", "", err
	}
	description, err := triage.RenderIssueDescription(f, a.knowledgeBase, r.Entry, a.jira.DescriptionTemplate)
	if err != nil {
		return "", "", err
	}
	customFields, err := triage.RenderCustomFields(a.jira.CustomFields, f, a.knowledgeBase, r.Entry)
	if err != nil {
		return "", "", err
	}
	// Labels use the finding's own severity/category, not the knowledge
	// base — Jira labels are conventionally short ASCII slugs, not free
	// text worth overriding per organization.
	labels := triage.IssueLabels(f, r.Entry, a.jira.ExtraLabels)
	return client.CreateIssue(ctx, summary, description, labels, customFields)
}

// createJiraIssues creates a Jira issue for every marked-or-selected row
// that's StatusConfirmed and doesn't have one yet. Runs the actual network
// calls in a goroutine and feeds results back via QueueUpdateDraw — tview
// is single-threaded, so doing this synchronously in the key-handler would
// freeze the whole UI for the duration of every HTTP request.
func (a *app) createJiraIssues() {
	if !a.jira.configured() {
		a.statusLine = "Jira not configured — set triage.jira in audit.yaml or pass --jira-url/--project/--issue-type."
		a.redraw()
		return
	}
	if a.jira.Token == "" {
		a.statusLine = "No Jira token — set --jira-token or $KUBECTL_AUDIT_JIRA_TOKEN, then retry."
		a.redraw()
		return
	}

	var targets []triage.Row
	for _, r := range a.markedOrSelectedTargets() {
		if r.Entry.Status == triage.StatusConfirmed && r.Entry.JiraIssueKey == "" {
			targets = append(targets, r)
		}
	}
	if len(targets) == 0 {
		a.statusLine = "No confirmed, not-yet-ticketed findings in the current selection — mark 'c' first."
		a.redraw()
		return
	}

	a.confirmBulkAction(fmt.Sprintf("Create %d Jira issue(s) in project %s?", len(targets), a.jira.ProjectKey), targets, func() {
		a.statusLine = fmt.Sprintf("Creating %d Jira issue(s)...", len(targets))
		a.redraw()

		client := triage.JiraClient{BaseURL: a.jira.BaseURL, Token: a.jira.Token, ProjectKey: a.jira.ProjectKey, IssueType: a.jira.IssueType}
		go func() {
			type result struct {
				id, key, url string
				err          error
			}
			results := make([]result, 0, len(targets))
			for _, r := range targets {
				key, url, err := a.createOneIssue(context.Background(), client, r)
				results = append(results, result{id: r.Entry.FindingID, key: key, url: url, err: err})
			}

			a.tv.QueueUpdateDraw(func() {
				now := time.Now()
				created, failed := 0, 0
				for _, res := range results {
					if res.err != nil {
						failed++
						continue
					}
					e := a.state.Entries[res.id]
					e.JiraIssueKey = res.key
					e.JiraIssueURL = res.url
					e.LastUpdated = now
					a.state.Entries[res.id] = e
					created++
				}
				a.statusLine = fmt.Sprintf("Created %d Jira issue(s), %d failed.", created, failed)
				a.marked = map[string]bool{}
				a.save()
				a.refresh()
				a.redraw()
			})
		}()
	})
}
