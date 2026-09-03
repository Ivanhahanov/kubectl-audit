// Package config defines the audit.yaml schema and loads/merges it with CLI overrides.
package config

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/thirdparty"

	"sigs.k8s.io/yaml"
)

// TargetMode selects where manifests are loaded from.
type TargetMode string

const (
	ModeCluster TargetMode = "cluster"
	ModeStatic  TargetMode = "static"
	ModeBoth    TargetMode = "both"
)

// TargetConfig describes where audited resources come from.
type TargetConfig struct {
	Mode       TargetMode `json:"mode,omitempty"`
	Context    string     `json:"context,omitempty"`
	Kubeconfig string     `json:"kubeconfig,omitempty"`
	// ClusterName overrides the report's Target field and every finding's
	// Source for a cluster-mode scan, in place of the raw kube-context name
	// (which defaults to "current-context" when --context isn't set, or can
	// be an unreadable cloud-provider ARN/UUID). Purely cosmetic — doesn't
	// affect which cluster is actually scanned.
	ClusterName   string   `json:"clusterName,omitempty"`
	Namespaces    []string `json:"namespaces,omitempty"`
	AllNamespaces bool     `json:"allNamespaces,omitempty"`
	Paths         []string `json:"paths,omitempty"`
	IncludeKinds  []string `json:"includeKinds,omitempty"`
	ExcludeKinds  []string `json:"excludeKinds,omitempty"`

	// ExcludeNamespaces are skipped entirely, regardless of mode. Defaults
	// to kube-public/kube-node-lease (see config.Default) — namespaces
	// with nothing worth auditing. kube-system is deliberately not
	// excluded by default: see loader.DefaultExcludedNamespaces. Ignored
	// when Namespaces (an explicit allowlist) is set.
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`

	// IncludeSystemRBAC, when true, keeps Role/ClusterRole/*Binding objects
	// named with the reserved "system:" prefix (Kubernetes' own built-in
	// RBAC) in scope. They're excluded by default: they're cluster-managed
	// and not something an operator can remediate.
	IncludeSystemRBAC bool `json:"includeSystemRBAC,omitempty"`

	// CheckUpdates, when true, makes a live HTTPS request to endoflife.date
	// to check the detected cluster version for available patch releases
	// and real EOL/support status — the only network call this tool ever
	// makes beyond the target cluster itself. Off by default so the tool
	// stays fully usable in air-gapped/restricted-network environments;
	// see internal/k8supdates.
	CheckUpdates bool `json:"checkUpdates,omitempty"`
	// ReadSecretValues, when true, lets this scan fetch Secret objects from
	// the cluster (in cluster mode) and evaluate policies against them (in
	// both cluster and static-manifest mode) — off by default. Every other
	// check this tool ships works from ConfigMaps, CRD specs, or workload
	// config alone; a small number of "is authentication left at its
	// documented default" checks structurally cannot be answered any other
	// way (the default/no-auth signal only exists as a Secret value, e.g.
	// a default admin password). Those checks are gated so they simply
	// don't run unless this is true — see docs/secrets-mode.md for exactly
	// which checks that affects, why they can never leak the actual secret
	// value into a finding (comparison-only against a known/expected
	// value, never a dynamic messageExpression), and the separate,
	// higher-privilege ClusterRole this requires (see rbac/clusterrole-with-secrets.yaml).
	ReadSecretValues bool `json:"readSecretValues,omitempty"`
}

// PoliciesConfig controls which policies are loaded.
type PoliciesConfig struct {
	Dirs    []string `json:"dirs,omitempty"`
	Disable []string `json:"disable,omitempty"`
	Builtin *bool    `json:"builtin,omitempty"`
}

// BuiltinEnabled reports whether bundled policies should load (default true).
func (p PoliciesConfig) BuiltinEnabled() bool {
	if p.Builtin == nil {
		return true
	}
	return *p.Builtin
}

// IsDisabled reports whether a policy ID was explicitly disabled.
func (p PoliciesConfig) IsDisabled(id string) bool {
	for _, d := range p.Disable {
		if d == id {
			return true
		}
	}
	return false
}

// OutputConfig controls report output paths and the CI failure threshold.
type OutputConfig struct {
	JSON     string `json:"json,omitempty"`
	Markdown string `json:"markdown,omitempty"`
	// CSV is a path to write findings as CSV, one row per finding — for
	// loading into a spreadsheet to sort/filter/assign owners. Empty (the
	// default) skips CSV output entirely; unlike JSON/Markdown there's no
	// default filename, since most invocations don't want it.
	CSV    string `json:"csv,omitempty"`
	FailOn string `json:"failOn,omitempty"`
	// Template is a path to a custom report.md.tpl (Go text/template). Empty
	// uses the embedded default template.
	Template string `json:"template,omitempty"`
	// Confluence is a path to write the report as Confluence Server/Data
	// Center wiki markup (h2., {code}, [text|url], ...) — ready to paste
	// into a Confluence page. Empty (the default) skips this output
	// entirely, same convention as CSV above. Cloud's Storage Format
	// (XHTML/ADF) is a different, unrelated format and out of scope here.
	Confluence string `json:"confluence,omitempty"`
	// ConfluenceTemplate is a path to a custom confluence.tpl (Go
	// text/template) for Confluence output. Empty uses the embedded
	// default Confluence template — same convention as Template above.
	ConfluenceTemplate string `json:"confluenceTemplate,omitempty"`
	// ReportLang selects which built-in Markdown template renders the
	// report's section labels/headings: "en" (default) or "ru" — a
	// ready-made Russian translation of the report skeleton (headings,
	// "Category"/"Remediation"/... labels), not a general i18n system. A
	// finding's own Title/Message/Remediation only change language if a
	// Russian knowledge base (triage.knowledgeBaseFile — the bundled
	// default already is one) overrides them; ReportLang only picks the
	// surrounding template. Ignored when Template is set — a custom
	// template always fully replaces the built-in one, same precedent as
	// every other --report-template override.
	ReportLang string `json:"reportLang,omitempty"`
	// Owner is a free-text "who's responsible for this report" field (a
	// name, team, or ticket queue) shown in the report header. Also used
	// by triage as the default Jira assignee for created issues (see
	// resolveJiraConfig/triage.RenderCustomFields) when it's a valid Jira
	// username — the same value serves both purposes, since it's the same
	// real-world "owner" concept. Never derived or validated. Empty (the
	// default) omits it from the report and skips auto-assignment.
	Owner string `json:"owner,omitempty"`
	// ReportView selects how the Markdown report's Findings section(s) are
	// structured: "check" (default) groups findings by check/policy ID —
	// each check's title/remediation shown once, followed by the resources
	// it fired on; "namespace" groups by namespace/resource instead, full
	// detail per finding; "both" renders the check-grouped view plus a
	// compact by-namespace index. On a large cluster "both" roughly doubles
	// the number of finding lines in the report (every finding listed once
	// per view) — "check" (or "namespace" for a per-team handoff) avoids
	// that duplication.
	ReportView string `json:"reportView,omitempty"`
	// NamespaceGroupThreshold collapses a check's "Affected resources" list
	// in the Markdown report: when a check whose message is identical for
	// every finding (true for essentially every VAP-based CEL check) fires
	// on the same Kind+Name pair in at least this many distinct namespaces,
	// those repeats are shown as a single row ("Kind/Name — repeated
	// identically in N namespaces: ...") instead of one bullet per
	// namespace. This targets the common multi-tenant shape where a
	// per-tenant namespace pattern (e.g. Capsule-provisioned tenant
	// namespaces, or any "one namespace per customer/env" convention)
	// deploys the same manifest into every namespace, so the same
	// misconfiguration is flagged once per namespace and drowns out
	// everything else in the report. Checks whose message differs per
	// finding (native analyzers like RBAC/PSS/control-plane, which build a
	// per-resource message) are never collapsed — only the uniform-message
	// case is safe to summarize without losing information. This is purely
	// a Markdown rendering choice: findings.json/CSV always list every
	// finding individually, so --fail-on gating, suppression accounting,
	// and CI tooling see no difference. 0 disables collapsing entirely.
	NamespaceGroupThreshold int `json:"namespaceGroupThreshold,omitempty"`
	// GroupByNamePattern extends NamespaceGroupThreshold's collapsing
	// beyond an identical literal Name repeated across namespaces: names
	// are first normalized by replacing generated-identifier-looking runs
	// (a UUID, or another long hex/digit run — see
	// internal/report.nameTemplate) with a placeholder, so e.g. per-tenant
	// Namespace objects literally named "usersvs-<uuid>" (a real shape
	// this catches — Namespace is cluster-scoped and every tenant's name
	// is unique, so it could never repeat under exact-name matching alone)
	// also collapse into one row instead of one per tenant. On by default;
	// a false positive here is rare (the identifier-shaped segment needs
	// to be a real UUID or an 8+ char hex / 4+ digit run — short version-
	// looking numbers like "app-v2" are deliberately excluded) but this
	// gives an explicit way to fall back to exact-name-only matching, or
	// disable collapsing entirely via NamespaceGroupThreshold: 0.
	GroupByNamePattern *bool `json:"groupByNamePattern,omitempty"`
}

// GroupByNamePatternEnabled reports the effective GroupByNamePattern value:
// the configured pointer if set, true otherwise (on by default — see the
// field's doc comment). A *bool (like PoliciesConfig.Builtin) because
// "false" and "not set" must be distinguishable when merging audit.yaml
// with CLI flags.
func (o OutputConfig) GroupByNamePatternEnabled() bool {
	if o.GroupByNamePattern == nil {
		return true
	}
	return *o.GroupByNamePattern
}

// ValidReportViews are the accepted values for ReportView.
var ValidReportViews = map[string]bool{"check": true, "namespace": true, "both": true}

// ValidReportLangs are the accepted values for ReportLang.
var ValidReportLangs = map[string]bool{"en": true, "ru": true}

// ComplianceConfig selects which requirement frameworks to score against
// (e.g. "cis", "fstec", "nsa" — see compliance-mappings/).
type ComplianceConfig struct {
	Frameworks []string `json:"frameworks,omitempty"`
}

// ExclusionMatch selects which resources an ExclusionRule applies to. At
// least one field must be set (an entirely empty Match would silently
// suppress every finding it's paired with — rejected at load time instead).
// All set fields must match (AND) for a resource to match this rule.
type ExclusionMatch struct {
	// Kind is an exact match against the finding's resource Kind (e.g.
	// "Deployment", "ServiceAccount", "Group" — the same Kind RBAC
	// findings use for non-object subjects like system:masters).
	Kind string `json:"kind,omitempty"`
	// Namespace is an exact match. Empty matches cluster-scoped resources
	// too — pair with Kind/Name/Labels to avoid over-matching.
	Namespace string `json:"namespace,omitempty"`
	// Name is matched via path.Match glob syntax (e.g. "legacy-*"), so a
	// plain literal name still works as an exact match.
	Name string `json:"name,omitempty"`
	// Labels must all be present with equal values on the source object.
	// Only matches resources this tool actually loaded from the API/
	// manifests (has real labels to check) — RBAC findings whose Resource
	// is a Group/User subject (not a loaded object) never match a Labels
	// rule.
	Labels map[string]string `json:"labels,omitempty"`
}

// ExclusionRule suppresses matching findings from a scan's pass/fail
// output. Suppressed findings are never silently dropped: they're counted
// and listed with Reason in the Markdown/JSON report (see report.Result),
// and excluded from the --fail-on gate and CSV export.
type ExclusionRule struct {
	// ID optionally names this rule so it can be referenced elsewhere —
	// currently only meaningful for this tool's own built-in rules (see
	// internal/suppress/builtin-exclusions.yaml), which can be disabled
	// individually via disableBuiltinExceptionIds. User-authored rules
	// don't need one.
	ID string `json:"id,omitempty"`
	// PolicyIDs restricts this rule to specific checks; empty or ["*"]
	// applies it to every check.
	PolicyIDs []string       `json:"policyIds,omitempty"`
	Match     ExclusionMatch `json:"match"`
	// Reason is shown in the report next to every finding this rule
	// suppresses — required, so a suppression always carries a paper
	// trail instead of becoming an unexplained gap.
	Reason string `json:"reason"`
}

// JiraConfig points `kubectl audit triage jira-sync` at a Jira Server/Data
// Center instance. Deliberately has no credential field: the Personal
// Access Token comes from the --jira-token flag or the
// KUBECTL_AUDIT_JIRA_TOKEN environment variable only — this file is the
// same git-committable audit.yaml every other config in this package
// lives in, and a secret has no business there.
type JiraConfig struct {
	// BaseURL is the Jira instance root, e.g. "https://jira.example.com"
	// (no trailing /rest/... path — jira-sync appends that itself).
	BaseURL string `json:"baseUrl,omitempty"`
	// ProjectKey is the Jira project new issues are created in (e.g. "SEC").
	ProjectKey string `json:"projectKey,omitempty"`
	// IssueType is the Jira issue type name for created issues (e.g. "Bug",
	// "Vulnerability" — whatever this Jira project's workflow expects).
	IssueType string `json:"issueType,omitempty"`
	// SummaryTemplate/DescriptionTemplate are paths to external Go
	// text/template files that fully replace the built-in issue summary/
	// description — e.g. to write them in a different language, or with
	// your own structure. Empty uses the embedded default (see
	// `kubectl-audit triage jira template dump`). Read fresh from disk on
	// every run — editing the file takes effect immediately, no rebuild.
	SummaryTemplate     string `json:"summaryTemplate,omitempty"`
	DescriptionTemplate string `json:"descriptionTemplate,omitempty"`
	// ExtraLabels are static labels added to every created issue beyond
	// the ones this tool derives automatically (severity, category, this
	// check's own knowledge-base labels) — e.g. a team or queue label your
	// Jira project expects.
	ExtraLabels []string `json:"extraLabels,omitempty"`
	// AutoLabels controls which of this tool's own automatic labels get
	// added to every created issue — independent per label, so e.g.
	// severity can be dropped (a Jira project that already tracks it in a
	// dedicated field) while keeping the others. ExtraLabels and each
	// check's own knowledge-base labels (see
	// findings.KnowledgeBaseEntry.Labels) always apply regardless of this
	// setting.
	AutoLabels AutoLabelsConfig `json:"autoLabels,omitempty"`
	// CustomFields are merged into every created issue's Jira fields,
	// keyed by Jira field ID (e.g. "customfield_10050"). A string value is
	// rendered as a Go template (same data as SummaryTemplate/
	// DescriptionTemplate — see internal/triage.RenderCustomFields), so it
	// can reference finding/triage data dynamically; any other
	// JSON-shaped value (a number, bool, or an object like {value: Prod}
	// for a Jira select-list field) is sent as-is. Like everything else in
	// this file, audit.yaml is git-committable — nothing secret belongs
	// in a custom field value.
	CustomFields map[string]any `json:"customFields,omitempty"`
}

// AutoLabelsConfig controls which of this tool's own automatic Jira labels
// get added to every created issue — a separate on/off per label (unlike a
// single "AutoLabels: false" switch) so e.g. severity can be dropped
// without also losing the "kubectl-audit"/category ones. Each field is on
// by default (nil = true); a *bool (like OutputConfig.GroupByNamePattern)
// because "false" and "not set" must be distinguishable.
type AutoLabelsConfig struct {
	// Tool is the fixed "kubectl-audit" marker label.
	Tool *bool `json:"tool,omitempty"`
	// Severity is the finding's own severity (e.g. "critical", "high").
	Severity *bool `json:"severity,omitempty"`
	// Category is the finding's own category (e.g. "workload-security").
	Category *bool `json:"category,omitempty"`
}

func (a AutoLabelsConfig) ToolEnabled() bool     { return a.Tool == nil || *a.Tool }
func (a AutoLabelsConfig) SeverityEnabled() bool { return a.Severity == nil || *a.Severity }
func (a AutoLabelsConfig) CategoryEnabled() bool { return a.Category == nil || *a.Category }

// TriageConfig configures `kubectl audit triage` — see docs/triage.md.
type TriageConfig struct {
	// StateFile is where triage decisions (status/notes/Jira links) are
	// persisted — a local, git-diffable YAML file, not a database. See
	// internal/triage.State.
	StateFile string     `json:"stateFile,omitempty"`
	Jira      JiraConfig `json:"jira,omitempty"`
	// KnowledgeBaseFile is a path to a YAML file (PolicyID -> {title,
	// description, remediation}) merged on top of the tool's bundled
	// knowledge base (see internal/triage.ResolveKnowledgeBase — the
	// bundle applies automatically, no config needed) — for correcting a
	// bundled entry or adding your organization's own wording/standards
	// for a check the bundle doesn't cover. Applied both when filing a
	// Jira ticket and in the triage TUI's detail view (so what you
	// preview is what gets filed — see internal/triage.Resolve). Not
	// nested under Jira: the detail view uses it independent of Jira
	// being configured at all. See `kubectl audit triage knowledge-base
	// dump` to inspect the bundle. Read fresh from disk on every run, no
	// rebuild.
	KnowledgeBaseFile string `json:"knowledgeBaseFile,omitempty"`
}

// ComponentsConfig lets a user extend this tool's built-in third-party
// component inventory (see internal/thirdparty) without forking or
// rebuilding — the same audit.yaml a krew-installed user already edits,
// rather than a separate file (there's no way to edit the embedded
// components.yaml short of rebuilding the binary).
type ComponentsConfig struct {
	// Extra components are merged with this tool's built-in inventory —
	// same schema as internal/thirdparty/components.yaml (name, category,
	// group, labels). Purely additive to the Detected Components table and
	// orphan/mismatch detection: adding an entry here does NOT create a
	// suppression exception by itself — pair a System-category entry with
	// your own `exclusions` rule (optionally with a matching `id`) for that.
	Extra []thirdparty.Component `json:"extra,omitempty"`
}

// AuditConfig is the root audit.yaml schema.
type AuditConfig struct {
	Target     TargetConfig     `json:"target,omitempty"`
	Policies   PoliciesConfig   `json:"policies,omitempty"`
	Output     OutputConfig     `json:"output,omitempty"`
	Compliance ComplianceConfig `json:"compliance,omitempty"`
	Exclusions []ExclusionRule  `json:"exclusions,omitempty"`
	// DisableBuiltinExceptions turns off this tool's built-in exclusion
	// rules for well-known, legitimately privileged infrastructure
	// DaemonSets (Cilium's agent, prometheus-node-exporter, ...) — see
	// internal/suppress.BuiltinRules. On by default; set true for a
	// stricter scan that shows literally everything, including violations
	// those components are documented to require.
	DisableBuiltinExceptions bool `json:"disableBuiltinExceptions,omitempty"`
	// DisableBuiltinExceptionIDs disables individually-named built-in
	// exclusion rules (by their ExclusionRule.ID — see
	// internal/suppress/builtin-exclusions.yaml for the current IDs) while
	// leaving the rest active. Finer-grained than DisableBuiltinExceptions,
	// which is all-or-nothing. An ID with no matching built-in rule is a
	// no-op (warned about, not an error, in case a rule is renamed/removed
	// across a version upgrade).
	DisableBuiltinExceptionIDs []string `json:"disableBuiltinExceptionIds,omitempty"`
	// Components extends the built-in third-party component inventory —
	// see ComponentsConfig.
	Components ComponentsConfig `json:"components,omitempty"`
	// Triage configures `kubectl audit triage` — see TriageConfig.
	Triage TriageConfig `json:"triage,omitempty"`
}

// Default returns an AuditConfig with sane production defaults.
func Default() *AuditConfig {
	return &AuditConfig{
		Target: TargetConfig{
			Mode:          ModeBoth,
			AllNamespaces: true,
			// Namespaces with nothing worth auditing; see
			// loader.DefaultExcludedNamespaces for why these two (and not
			// kube-system) are excluded by default. Override with an
			// explicit excludeNamespaces (possibly []) or a -n allowlist.
			ExcludeNamespaces: []string{"kube-public", "kube-node-lease"},
		},
		Policies: PoliciesConfig{
			Builtin: boolPtr(true),
		},
		Output: OutputConfig{
			JSON:                    "findings.json",
			Markdown:                "report.md",
			FailOn:                  "high",
			ReportView:              "check",
			ReportLang:              "en",
			NamespaceGroupThreshold: 3,
		},
		Compliance: ComplianceConfig{
			Frameworks: []string{"cis"},
		},
		Triage: TriageConfig{
			StateFile: "triage-state.yaml",
		},
	}
}

func boolPtr(b bool) *bool { return &b }

// Load reads audit.yaml from path (if non-empty) and merges it onto the
// defaults. If path is empty, defaults are returned unchanged (no file is
// required to run the tool). If path is non-empty and unreadable, an error
// is returned.
func Load(path string) (*AuditConfig, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	// UnmarshalStrict (not Unmarshal): a typo'd field name (e.g.
	// "namespceGroupThreshold") must fail loudly. Silently falling back to
	// the zero value/default for a misspelled security-relevant setting is
	// worse than an error — the tool would just run with a config the user
	// didn't actually intend, with no indication anything was ignored.
	if err := yaml.UnmarshalStrict(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if err := validateExclusions(cfg.Exclusions); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if err := validateExtraComponents(cfg.Components.Extra); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	for i, c := range cfg.Components.Extra {
		if c.Category == "" {
			cfg.Components.Extra[i].Category = thirdparty.CategoryApplication
		}
	}
	expandTriagePaths(&cfg.Triage)
	return cfg, nil
}

// expandTriagePaths expands a leading "~/" in the triage config's own
// file-path fields — StateFile, KnowledgeBaseFile, and the Jira summary/
// description templates — the same convenience `~/.kube/config` users
// expect from a path, but that Go's os.ReadFile doesn't do on its own (no
// shell involved to expand it). Lets an audit.yaml living in
// ~/.kubectl-audit/ (see resolveConfigPath in internal/cli) reference
// sibling files there — "~/.kubectl-audit/knowledge-base.yaml" — without
// spelling out the full absolute path. A path not starting with "~/" is
// left untouched, so ordinary CWD-relative paths (e.g. a project's own
// checked-in audit.yaml) behave exactly as before.
func expandTriagePaths(t *TriageConfig) {
	t.StateFile = expandHome(t.StateFile)
	t.KnowledgeBaseFile = expandHome(t.KnowledgeBaseFile)
	t.Jira.SummaryTemplate = expandHome(t.Jira.SummaryTemplate)
	t.Jira.DescriptionTemplate = expandHome(t.Jira.DescriptionTemplate)
}

func expandHome(p string) string {
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[len("~/"):])
}

// validateExtraComponents rejects entries with neither Group nor Labels
// set — such an entry would never match anything, which is almost always
// a typo rather than an intentional inert placeholder.
func validateExtraComponents(components []thirdparty.Component) error {
	for i, c := range components {
		if strings.TrimSpace(c.Name) == "" {
			return fmt.Errorf("components.extra[%d]: name is required", i)
		}
		if c.Group == "" && len(c.Labels) == 0 {
			return fmt.Errorf("components.extra[%d] (%s): must set at least one of group or labels", i, c.Name)
		}
	}
	return nil
}

// validateExclusions rejects rules that would silently suppress more than
// intended: a Reason is mandatory (so every suppression carries a paper
// trail), and Match must set at least one field (an empty Match would
// suppress every finding for every resource).
func validateExclusions(rules []ExclusionRule) error {
	for i, r := range rules {
		if strings.TrimSpace(r.Reason) == "" {
			return fmt.Errorf("exclusions[%d]: reason is required", i)
		}
		m := r.Match
		if m.Kind == "" && m.Namespace == "" && m.Name == "" && len(m.Labels) == 0 {
			return fmt.Errorf("exclusions[%d]: match must set at least one of kind, namespace, name, or labels", i)
		}
		// match.name is matched via path.Match glob syntax (see
		// suppress.matchesResource) — a syntax error there (e.g. an
		// unterminated "[" character class) would otherwise be silently
		// treated as "never matches" on every single finding evaluated
		// against this rule, forever, with no visible sign the rule is
		// broken rather than just narrowly scoped. Reject it here instead,
		// same as the two structural checks above.
		if m.Name != "" {
			if _, err := path.Match(m.Name, ""); err != nil {
				return fmt.Errorf("exclusions[%d]: match.name %q is not a valid glob pattern: %w", i, m.Name, err)
			}
		}
	}
	return nil
}

// FailOnSeverity resolves the configured failOn threshold, treating
// "none"/"" as "never fail".
func (c *AuditConfig) FailOnSeverity() (findings.Severity, bool) {
	switch normalize(c.Output.FailOn) {
	case "", "none":
		return "", false
	default:
		return findings.ParseSeverity(c.Output.FailOn), true
	}
}

func normalize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}
