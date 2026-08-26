package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/report"
	"github.com/ivanhahanov/kubectl-audit/internal/triage"
	"github.com/ivanhahanov/kubectl-audit/internal/triage/tui"
)

var (
	flagTriageFindings          string
	flagTriageState             string
	flagTriageStatus            string
	flagTriageIncludeSuppressed bool
	flagTriageJiraURL           string
	flagTriageJiraProject       string
	flagTriageJiraIssueType     string
	flagTriageJiraToken         string
)

func newTriageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "triage",
		Short: "Interactively review findings.json and record confirmed/false-positive/won't-fix decisions.",
		Long: "Opens an interactive TUI (see docs/triage.md) joining a scan's findings.json with a " +
			"persisted triage decision per finding, so a human expert can work through what an automated " +
			"scan flagged and end up with a filtered \"what actually needs fixing\" list — including " +
			"guidance (audit.k8s-auditor.io/verification-steps) on how to confirm each one is a true " +
			"positive before acting on it.",
		RunE: runTriageOpen,
	}
	cmd.PersistentFlags().StringVar(&flagTriageFindings, "findings", "", "path to findings.json (default: from config, \"findings.json\")")
	cmd.PersistentFlags().StringVar(&flagTriageState, "state", "", "path to the triage state file (default: from config, \"triage-state.yaml\")")
	// Jira flags live on the parent so both the interactive TUI's 'j'
	// hotkey and `jira-sync` resolve them identically.
	cmd.PersistentFlags().StringVar(&flagTriageJiraURL, "jira-url", "", "Jira base URL (default: from config, triage.jira.baseUrl)")
	cmd.PersistentFlags().StringVar(&flagTriageJiraProject, "project", "", "Jira project key (default: from config, triage.jira.projectKey)")
	cmd.PersistentFlags().StringVar(&flagTriageJiraIssueType, "issue-type", "", "Jira issue type name (default: from config, triage.jira.issueType)")
	cmd.PersistentFlags().StringVar(&flagTriageJiraToken, "jira-token", "", "Jira Personal Access Token (default: $KUBECTL_AUDIT_JIRA_TOKEN — never stored in audit.yaml)")
	cmd.AddCommand(newTriageExportCmd())
	cmd.AddCommand(newTriageJiraSyncCmd())
	cmd.AddCommand(newTriageJiraCmd())
	cmd.AddCommand(newTriageKnowledgeBaseCmd())
	return cmd
}

// resolveTriagePaths applies the same audit.yaml-then-flag-override
// resolution every other command in this package uses (see
// loadEffectiveConfig) for the two paths triage commands share.
func resolveTriagePaths(cmd *cobra.Command) (findingsPath, statePath string, err error) {
	cfg, err := loadEffectiveConfig(cmd)
	if err != nil {
		return "", "", err
	}
	findingsPath = cfg.Output.JSON
	if flagTriageFindings != "" {
		findingsPath = flagTriageFindings
	}
	statePath = cfg.Triage.StateFile
	if flagTriageState != "" {
		statePath = flagTriageState
	}
	return findingsPath, statePath, nil
}

// resolveJiraConfig applies audit.yaml-then-flag-override resolution for
// Jira connection details, shared by the TUI's 'j' hotkey and `jira-sync`.
// The token additionally falls back to $KUBECTL_AUDIT_JIRA_TOKEN — never
// audit.yaml, which has no field for it at all (see config.JiraConfig).
func resolveJiraConfig(cmd *cobra.Command) (tui.JiraConfig, error) {
	cfg, err := loadEffectiveConfig(cmd)
	if err != nil {
		return tui.JiraConfig{}, err
	}
	jc := tui.JiraConfig{
		BaseURL:      cfg.Triage.Jira.BaseURL,
		ProjectKey:   cfg.Triage.Jira.ProjectKey,
		IssueType:    cfg.Triage.Jira.IssueType,
		ExtraLabels:  cfg.Triage.Jira.ExtraLabels,
		CustomFields: cfg.Triage.Jira.CustomFields,
	}
	if flagTriageJiraURL != "" {
		jc.BaseURL = flagTriageJiraURL
	}
	if flagTriageJiraProject != "" {
		jc.ProjectKey = flagTriageJiraProject
	}
	if flagTriageJiraIssueType != "" {
		jc.IssueType = flagTriageJiraIssueType
	}
	jc.Token = flagTriageJiraToken
	if jc.Token == "" {
		jc.Token = os.Getenv("KUBECTL_AUDIT_JIRA_TOKEN")
	}
	// SummaryTemplate/DescriptionTemplate are file paths in audit.yaml —
	// loadTemplateFile (internal/cli/orchestrate.go) already does exactly
	// "empty path -> "", else read the file", the same fallback rule
	// output.template uses for the Markdown report. Read fresh every run,
	// so editing the pointed-at file never needs a rebuild.
	jc.SummaryTemplate, err = loadTemplateFile(cfg.Triage.Jira.SummaryTemplate)
	if err != nil {
		return tui.JiraConfig{}, err
	}
	jc.DescriptionTemplate, err = loadTemplateFile(cfg.Triage.Jira.DescriptionTemplate)
	if err != nil {
		return tui.JiraConfig{}, err
	}
	return jc, nil
}

// resolveKnowledgeBase loads triage.knowledgeBaseFile (see
// config.TriageConfig) — the same empty-path-means-nothing convention as
// loadTemplateFile. Independent of Jira: the triage TUI's detail view
// applies it too, so it's resolved regardless of whether Jira is even
// configured.
func resolveKnowledgeBase(cmd *cobra.Command) (map[string]findings.KnowledgeBaseEntry, error) {
	cfg, err := loadEffectiveConfig(cmd)
	if err != nil {
		return nil, err
	}
	return triage.ResolveKnowledgeBase(cfg.Triage.KnowledgeBaseFile)
}

func loadFindingsAndState(cmd *cobra.Command) (target string, all []findings.Finding, suppressed []report.SuppressedFinding, state *triage.State, statePath string, err error) {
	findingsPath, statePath, err := resolveTriagePaths(cmd)
	if err != nil {
		return "", nil, nil, nil, "", err
	}
	target, all, suppressed, err = triage.LoadFindings(findingsPath)
	if err != nil {
		return "", nil, nil, nil, "", fmt.Errorf("%w (run `kubectl audit scan --output-json %s` first)", err, findingsPath)
	}
	state, err = triage.LoadState(statePath)
	if err != nil {
		return "", nil, nil, nil, "", err
	}
	return target, all, suppressed, state, statePath, nil
}

func runTriageOpen(cmd *cobra.Command, args []string) error {
	findingsPath, statePath, err := resolveTriagePaths(cmd)
	if err != nil {
		return err
	}
	target, all, suppressed, state, _, err := loadFindingsAndState(cmd)
	if err != nil {
		return err
	}
	jiraCfg, err := resolveJiraConfig(cmd)
	if err != nil {
		return err
	}
	kb, err := resolveKnowledgeBase(cmd)
	if err != nil {
		return err
	}
	cfg, err := loadEffectiveConfig(cmd)
	if err != nil {
		return err
	}
	// Merge once up front purely to apply the StatusResolved transition
	// and persist it before the TUI's own internal Merge calls (which
	// recompute the same thing on every redraw) — so even a user who
	// immediately quits without touching anything still gets resolved
	// findings recorded.
	_ = triage.Merge(all, suppressed, state, time.Now())
	if err := triage.SaveState(statePath, state); err != nil {
		return err
	}

	return tui.Run(all, suppressed, state, tui.Config{
		Target:         target,
		FindingsPath:   findingsPath,
		StatePath:      statePath,
		Jira:           jiraCfg,
		KnowledgeBase:  kb,
		DedupThreshold: cfg.Output.NamespaceGroupThreshold,
	})
}

func newTriageExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Non-interactively dump triage-joined findings, optionally filtered by --status, as JSON.",
		Long: "Useful standalone (no Jira needed) to hand a reviewed list to another tool or process — " +
			"e.g. `kubectl audit triage export --status confirmed` for exactly the findings a human has " +
			"confirmed are real and worth fixing.",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, all, suppressed, state, _, err := loadFindingsAndState(cmd)
			if err != nil {
				return err
			}
			if !flagTriageIncludeSuppressed {
				suppressed = nil
			}
			rows := triage.Merge(all, suppressed, state, time.Now())

			type exportRow struct {
				Finding        *findings.Finding `json:"finding,omitempty"`
				Entry          triage.Entry      `json:"triage"`
				Suppressed     bool              `json:"suppressed,omitempty"`
				SuppressReason string            `json:"suppressReason,omitempty"`
			}
			var out []exportRow
			for _, r := range rows {
				if flagTriageStatus != "" && string(displayStatus(r)) != flagTriageStatus {
					continue
				}
				out = append(out, exportRow{Finding: r.Finding, Entry: r.Entry, Suppressed: r.Suppressed, SuppressReason: r.SuppressReason})
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		},
	}
	cmd.Flags().StringVar(&flagTriageStatus, "status", "", "only export findings with this triage status (confirmed|false_positive|wont_fix|duplicate|needs_info|new|resolved); default: all")
	cmd.Flags().BoolVar(&flagTriageIncludeSuppressed, "include-suppressed", false, "also include findings an exclusion rule suppressed (excluded by default, matching the Markdown report's own opt-in visibility)")
	return cmd
}

func displayStatus(r triage.Row) triage.Status {
	if r.Suppressed {
		return "suppressed"
	}
	if r.Entry.Status == "" {
		return triage.StatusNew
	}
	return r.Entry.Status
}

func newTriageJiraSyncCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "jira-sync",
		Short: "Create Jira issues for confirmed findings that don't have one yet.",
		Long: "Reads triage state for status=confirmed entries with no Jira issue yet, previews (default) " +
			"or creates a Jira Server/Data Center issue (REST API v2) for each, and writes the issue " +
			"key/URL back into state so a re-run never double-creates. The Personal Access Token never " +
			"comes from audit.yaml — pass --jira-token or set KUBECTL_AUDIT_JIRA_TOKEN.",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, all, suppressed, state, statePath, err := loadFindingsAndState(cmd)
			if err != nil {
				return err
			}
			jiraCfg, err := resolveJiraConfig(cmd)
			if err != nil {
				return err
			}
			kb, err := resolveKnowledgeBase(cmd)
			if err != nil {
				return err
			}
			if jiraCfg.BaseURL == "" || jiraCfg.ProjectKey == "" || jiraCfg.IssueType == "" {
				return fmt.Errorf("jira-sync needs a Jira base URL, project key, and issue type — set them via --jira-url/--project/--issue-type or triage.jira in audit.yaml")
			}

			rows := triage.Merge(all, suppressed, state, time.Now())
			var targets []triage.Row
			for _, r := range rows {
				if r.Entry.Status == triage.StatusConfirmed && r.Entry.JiraIssueKey == "" && r.Finding != nil {
					targets = append(targets, r)
				}
			}
			if len(targets) == 0 {
				fmt.Println("No confirmed findings without a Jira issue yet — nothing to do.")
				return nil
			}

			if dryRun {
				fmt.Printf("Dry run: would create %d Jira issue(s) in project %s (issue type %q):\n", len(targets), jiraCfg.ProjectKey, jiraCfg.IssueType)
				for _, r := range targets {
					summary, err := triage.RenderIssueSummary(*r.Finding, kb, r.Entry, jiraCfg.SummaryTemplate)
					if err != nil {
						return fmt.Errorf("rendering summary for %s: %w", r.Finding.ID, err)
					}
					fmt.Printf("  - %s\n", summary)
				}
				fmt.Println("\nRe-run with --dry-run=false to actually create these.")
				return nil
			}
			if jiraCfg.Token == "" {
				return fmt.Errorf("no Jira token: set --jira-token or KUBECTL_AUDIT_JIRA_TOKEN")
			}

			client := triage.JiraClient{BaseURL: jiraCfg.BaseURL, Token: jiraCfg.Token, ProjectKey: jiraCfg.ProjectKey, IssueType: jiraCfg.IssueType}
			var created, failed int
			for _, r := range targets {
				summary, err := triage.RenderIssueSummary(*r.Finding, kb, r.Entry, jiraCfg.SummaryTemplate)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to render summary for %s: %v\n", r.Finding.ID, err)
					failed++
					continue
				}
				description, err := triage.RenderIssueDescription(*r.Finding, kb, r.Entry, jiraCfg.DescriptionTemplate)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to render description for %s: %v\n", r.Finding.ID, err)
					failed++
					continue
				}
				customFields, err := triage.RenderCustomFields(jiraCfg.CustomFields, *r.Finding, kb, r.Entry)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to render custom fields for %s: %v\n", r.Finding.ID, err)
					failed++
					continue
				}
				labels := triage.IssueLabels(*r.Finding, r.Entry, jiraCfg.ExtraLabels)
				key, url, err := client.CreateIssue(cmd.Context(), summary, description, labels, customFields)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to create issue for %s: %v\n", r.Finding.ID, err)
					failed++
					continue
				}
				e := r.Entry
				e.JiraIssueKey = key
				e.JiraIssueURL = url
				e.LastUpdated = time.Now()
				state.Entries[r.Finding.ID] = e
				fmt.Printf("Created %s for %s\n", key, summary)
				created++
			}
			if err := triage.SaveState(statePath, state); err != nil {
				return err
			}
			fmt.Printf("Created %d issue(s), %d failure(s).\n", created, failed)
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", true, "preview what would be created without contacting Jira (default true — pass --dry-run=false to actually create issues)")
	return cmd
}

// newTriageJiraCmd groups Jira-template utilities — mirrors
// newTemplateCmd/newTemplateDumpCmd (internal/cli/template_cmd.go) for the
// Markdown report, one level deeper since it's triage-specific.
func newTriageJiraCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jira",
		Short: "Jira issue template utilities.",
	}
	cmd.AddCommand(newTriageJiraTemplateCmd())
	return cmd
}

// newTriageKnowledgeBaseCmd is a sibling of export/jira-sync, not nested
// under jira — the knowledge base overrides ticket content but also drives
// the triage TUI's detail view independent of Jira being configured at
// all (see resolveKnowledgeBase).
func newTriageKnowledgeBaseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "knowledge-base",
		Short: "Knowledge base utilities.",
	}
	cmd.AddCommand(newTriageKnowledgeBaseDumpCmd())
	return cmd
}

func newTriageKnowledgeBaseDumpCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Write a ready-made knowledge base to disk, as a starting point for triage.knowledgeBaseFile customization.",
		Long: "A starting point for your organization's own ticket wording: dump it, edit whichever " +
			"entries you want (your own title/description/remediation for a check, in your own words " +
			"or language), save as your own (possibly smaller) file, and point triage.knowledgeBaseFile " +
			"at it. Entries you don't touch simply aren't used — you don't need to keep every one. No " +
			"rebuild needed: the file is read fresh on every `triage jira-sync`/TUI 'j'/'enter' run.",
		RunE: func(cmd *cobra.Command, args []string) error {
			src := triage.StarterKnowledgeBase()
			if out == "" {
				fmt.Print(src)
				return nil
			}
			if err := os.WriteFile(out, []byte(src), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", out, err)
			}
			fmt.Printf("Wrote starter knowledge base to %s\n", out)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "file to write (default: stdout)")
	return cmd
}

func newTriageJiraTemplateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Jira issue summary/description template utilities.",
	}
	cmd.AddCommand(newTriageJiraTemplateDumpCmd())
	return cmd
}

func newTriageJiraTemplateDumpCmd() *cobra.Command {
	var kind, out string
	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Write the built-in Jira summary/description template to disk, as a starting point for triage.jira.summaryTemplate/descriptionTemplate customization.",
		Long: "A starting point for customizing (or translating) the Jira issue text this tool creates — " +
			"dump it, edit the copy however you like (different language, different structure), and point " +
			"triage.jira.summaryTemplate or descriptionTemplate at your copy. No rebuild needed: the file " +
			"is read fresh on every `triage jira-sync`/TUI 'j' run.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var src string
			switch kind {
			case "summary":
				src = triage.DefaultSummaryTemplate()
			case "description":
				src = triage.DefaultDescriptionTemplate()
			default:
				return fmt.Errorf("--kind must be summary or description, got %q", kind)
			}
			if out == "" {
				fmt.Print(src)
				return nil
			}
			if err := os.WriteFile(out, []byte(src), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", out, err)
			}
			fmt.Printf("Wrote default %s template to %s\n", kind, out)
			return nil
		},
	}
	cmd.Flags().StringVar(&kind, "kind", "", "which template to dump: summary|description (required)")
	cmd.Flags().StringVar(&out, "out", "", "file to write (default: stdout)")
	cmd.MarkFlagRequired("kind")
	return cmd
}
