package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rivo/tview"

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
	labels := triage.IssueLabels(f, a.knowledgeBase, a.jira.ExtraLabels)
	return client.CreateIssue(ctx, summary, description, labels, customFields)
}

// jiraPreviewText renders exactly what filing a Jira ticket for r would
// send — calling the same triage.RenderIssueSummary/RenderIssueDescription/
// RenderCustomFields/IssueLabels createOneIssue itself uses, so this can
// never drift out of sync with what 'j' actually creates. This is the fix
// for detailText's fixed layout not reflecting a custom
// summaryTemplate/descriptionTemplate — the exact "what you preview is
// what gets filed" gap a real WYSIWYG guarantee requires. Rendered
// summary/description/custom-field VALUES are tview.Escape'd before
// display: they're free-form, user-configured text (commonly Jira wiki
// markup, e.g. "[link text|http://...]"), and without escaping, a literal
// "[...]" in there would be misread as a tview color/region tag by this
// same TextView.
func (a *app) jiraPreviewText(r triage.Row) string {
	var b strings.Builder
	if !a.jira.configured() {
		b.WriteString("[yellow]Jira is not configured.[white] Set triage.jira (baseUrl/projectKey/issueType) in " +
			"audit.yaml, or pass --jira-url/--project/--issue-type — see docs/triage.md.\n")
		return b.String()
	}
	if r.Finding == nil {
		b.WriteString("[yellow]This finding is no longer produced by the latest scan — nothing to file.[white]\n")
		return b.String()
	}

	f := *r.Finding
	fmt.Fprintf(&b, "[yellow]Project:[white] %s      [yellow]Issue type:[white] %s\n", a.jira.ProjectKey, a.jira.IssueType)

	if summary, err := triage.RenderIssueSummary(f, a.knowledgeBase, r.Entry, a.jira.SummaryTemplate); err != nil {
		fmt.Fprintf(&b, "\n[red]Summary template error:[white] %v\n", err)
	} else {
		fmt.Fprintf(&b, "\n[yellow]Summary:[white]\n%s\n", tview.Escape(summary))
	}

	if labels := triage.IssueLabels(f, a.knowledgeBase, a.jira.ExtraLabels); len(labels) > 0 {
		fmt.Fprintf(&b, "\n[yellow]Labels:[white] %s\n", strings.Join(labels, ", "))
	}

	if len(a.jira.CustomFields) > 0 {
		if fields, err := triage.RenderCustomFields(a.jira.CustomFields, f, a.knowledgeBase, r.Entry); err != nil {
			fmt.Fprintf(&b, "\n[red]Custom fields template error:[white] %v\n", err)
		} else {
			b.WriteString("\n[yellow]Custom fields:[white]\n")
			keys := make([]string, 0, len(fields))
			for k := range fields {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				data, err := json.Marshal(fields[k])
				if err != nil {
					data = []byte(fmt.Sprintf("%v", fields[k]))
				}
				fmt.Fprintf(&b, "  %s: %s\n", k, tview.Escape(string(data)))
			}
		}
	}

	if description, err := triage.RenderIssueDescription(f, a.knowledgeBase, r.Entry, a.jira.DescriptionTemplate); err != nil {
		fmt.Fprintf(&b, "\n[red]Description template error:[white] %v\n", err)
	} else {
		fmt.Fprintf(&b, "\n[yellow]Description:[white]\n%s\n", tview.Escape(description))
	}

	return b.String()
}

// jiraFilingStatus reports whether 'j' would actually do anything for r
// right now — "" if it would (CONFIRMED, not yet filed), otherwise a short
// note explaining why not. Deliberately kept out of jiraPreviewText's body:
// this is meta-information about the filing ACTION, not part of the
// rendered ticket content itself, so it belongs in the hint/status bar
// (flashed when entering preview — see openDetail's 'v' handler) rather
// than mixed into the same scrollable text a triager is reading to review
// the ticket.
func jiraFilingStatus(r triage.Row) string {
	if r.Entry.JiraIssueKey != "" {
		return fmt.Sprintf("already filed as %s (%s)", r.Entry.JiraIssueKey, r.Entry.JiraIssueURL)
	}
	if r.Entry.Status != triage.StatusConfirmed {
		return "not yet CONFIRMED — 'j' won't create a ticket until you confirm it ('c')"
	}
	return ""
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
