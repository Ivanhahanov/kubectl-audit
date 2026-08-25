package triage

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

//go:embed templates/summary.tpl
var defaultSummaryTemplateSource string

//go:embed templates/description.tpl
var defaultDescriptionTemplateSource string

// DefaultSummaryTemplate and DefaultDescriptionTemplate return the built-in
// Jira issue templates, e.g. for `kubectl-audit triage jira template dump`
// to give users a starting point to translate/restructure — customization
// always happens by pointing triage.jira.summaryTemplate/
// descriptionTemplate at an external file (see RenderIssueSummary/
// RenderIssueDescription); nothing here ever requires a rebuild.
func DefaultSummaryTemplate() string     { return defaultSummaryTemplateSource }
func DefaultDescriptionTemplate() string { return defaultDescriptionTemplateSource }

// IssueTemplateData is what every Jira issue template (summary,
// description, and each triage.jira.customFields string value) renders
// against.
type IssueTemplateData struct {
	Finding findings.Finding
	Entry   Entry
}

func issueTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"join": func(elems []string, sep string) string { return strings.Join(elems, sep) },
	}
}

// renderIssueTemplate parses and executes tplSource (falling back to def
// when tplSource is empty) against an IssueTemplateData built from f/e —
// the shared mechanism behind RenderIssueSummary, RenderIssueDescription,
// and RenderCustomFields.
func renderIssueTemplate(name, tplSource, def string, f findings.Finding, e Entry) (string, error) {
	if tplSource == "" {
		tplSource = def
	}
	tpl, err := template.New(name).Funcs(issueTemplateFuncs()).Parse(tplSource)
	if err != nil {
		return "", fmt.Errorf("parsing %s template: %w", name, err)
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, IssueTemplateData{Finding: f, Entry: e}); err != nil {
		return "", fmt.Errorf("executing %s template: %w", name, err)
	}
	return buf.String(), nil
}

// RenderIssueSummary and RenderIssueDescription build a Jira issue's
// summary/description for a confirmed finding. An empty tplSource uses the
// embedded default (DefaultSummaryTemplate/DefaultDescriptionTemplate); a
// non-empty one (loaded from triage.jira.summaryTemplate/
// descriptionTemplate — see docs/triage.md) fully replaces it, e.g. for a
// different language or structure. The default description embeds a
// back-link ("kubectl-audit finding: <id>") purely for a human reader
// tracing the issue back to its source — idempotency itself (never
// double-creating on a re-run) is handled by the caller checking
// Entry.JiraIssueKey, not by searching Jira for this text.
func RenderIssueSummary(f findings.Finding, e Entry, tplSource string) (string, error) {
	s, err := renderIssueTemplate("summary", tplSource, defaultSummaryTemplateSource, f, e)
	return strings.TrimSpace(s), err
}

func RenderIssueDescription(f findings.Finding, e Entry, tplSource string) (string, error) {
	return renderIssueTemplate("description", tplSource, defaultDescriptionTemplateSource, f, e)
}

// RenderCustomFields renders triage.jira.customFields into the shape a
// Jira create-issue request's `fields` object expects: a string value is
// rendered as a Go template against the same IssueTemplateData as the
// summary/description (so e.g. "{{.Finding.Severity}}" works); any other
// JSON-shaped value (number, bool, or a nested object/array — e.g.
// {"value": "Prod"} for a Jira select-list field) passes through
// unchanged, since there's nothing to template. Returns nil for an empty
// map, so callers can omit "fields" merging entirely when there's nothing
// configured.
func RenderCustomFields(fields map[string]any, f findings.Finding, e Entry) (map[string]any, error) {
	if len(fields) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		s, ok := v.(string)
		if !ok {
			out[k] = v
			continue
		}
		rendered, err := renderIssueTemplate("customFields."+k, s, s, f, e)
		if err != nil {
			return nil, fmt.Errorf("customFields[%s]: %w", k, err)
		}
		out[k] = rendered
	}
	return out, nil
}

// JiraClient creates issues in a Jira Server/Data Center instance via REST
// API v2 (not Cloud's v3 — this project's Jira flavor, confirmed with the
// user). Auth is a Bearer Personal Access Token only. This struct is a
// purely in-memory runtime value built from a CLI flag/environment
// variable at command execution time — never serialized, unlike
// config.JiraConfig (the audit.yaml-persisted counterpart), which
// deliberately has no token field at all.
type JiraClient struct {
	BaseURL    string
	Token      string
	ProjectKey string
	IssueType  string
	HTTPClient *http.Client
}

// jiraRef is Jira's own "refer to an object by key or name" shape, used
// identically for both project and issuetype references in the v2 API.
type jiraRef struct {
	Key  string `json:"key,omitempty"`
	Name string `json:"name,omitempty"`
}

type jiraIssueResponse struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Self string `json:"self"`
}

// CreateIssue creates one Jira issue and returns its key (e.g. "SEC-123")
// and a browsable URL. customFields (see RenderCustomFields) are merged
// into the same request `fields` object as project/summary/description/
// issuetype/labels — the "fields" object is built as a plain map rather
// than a fixed struct specifically so arbitrary custom-field keys
// (customfield_10050, ...) can sit alongside the standard ones.
func (c JiraClient) CreateIssue(ctx context.Context, summary, description string, labels []string, customFields map[string]any) (key, url string, err error) {
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	fields := map[string]any{
		"project":     jiraRef{Key: c.ProjectKey},
		"summary":     summary,
		"description": description,
		"issuetype":   jiraRef{Name: c.IssueType},
	}
	if len(labels) > 0 {
		fields["labels"] = labels
	}
	for k, v := range customFields {
		fields[k] = v
	}

	data, err := json.Marshal(map[string]any{"fields": fields})
	if err != nil {
		return "", "", fmt.Errorf("encoding Jira issue request: %w", err)
	}

	endpoint := strings.TrimRight(c.BaseURL, "/") + "/rest/api/2/issue"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return "", "", fmt.Errorf("building request to %s: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("creating Jira issue at %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("Jira returned %s creating an issue: %s", resp.Status, string(body))
	}

	var out jiraIssueResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", fmt.Errorf("parsing Jira response: %w", err)
	}
	return out.Key, strings.TrimRight(c.BaseURL, "/") + "/browse/" + out.Key, nil
}

// IssueLabels builds Jira labels from a finding's severity/category and
// any triage tags, plus extra (triage.jira.extraLabels — static labels a
// user wants on every created issue beyond what's auto-derived, e.g. their
// own team/queue label). Jira labels can't contain whitespace;
// sanitizeLabel replaces it with "-" and drops anything else Jira's label
// validation would reject rather than risk the whole create request
// failing over one bad label. Duplicates (after sanitizing) are dropped.
func IssueLabels(f findings.Finding, e Entry, extra []string) []string {
	var labels []string
	seen := map[string]bool{}
	add := func(raw string) {
		l := sanitizeLabel(raw)
		if l == "" || seen[l] {
			return
		}
		seen[l] = true
		labels = append(labels, l)
	}
	add("kubectl-audit")
	add(string(f.Severity))
	add(f.Category)
	for _, t := range e.Tags {
		add(t)
	}
	for _, t := range extra {
		add(t)
	}
	return labels
}

var labelInvalidChars = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func sanitizeLabel(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "-")
	return labelInvalidChars.ReplaceAllString(strings.ToLower(s), "")
}
