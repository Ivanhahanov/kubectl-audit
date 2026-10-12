// Package cli implements the kubectl-audit command surface.
package cli

import (
	"github.com/spf13/cobra"
)

var (
	flagConfig                     string
	flagContextName                string
	flagClusterName                string
	flagKubeconfig                 string
	flagMode                       string
	flagFiles                      []string
	flagNamespaces                 []string
	flagAllNamespaces              bool
	flagExcludeNamespaces          []string
	flagIncludeSystemRBAC          bool
	flagCheckUpdates               bool
	flagReadSecretValues           bool
	flagPolicyDirs                 []string
	flagOutputs                    []string
	flagFailOn                     string
	flagMinSeverity                string
	flagFrameworks                 []string
	flagFrameworksOnly             bool
	flagReportTemplate             string
	flagConfluenceTemplate         string
	flagReportLang                 string
	flagOwner                      string
	flagReportView                 string
	flagNamespaceGroupThreshold    int
	flagGroupByNamePattern         bool
	flagShowRemediation            bool
	flagNoBuiltinExceptions        bool
	flagDisableBuiltinExceptionIDs []string
	flagRequestTimeout             string
	flagVerbose                    bool
)

// NewRootCmd builds the kubectl-audit command tree.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "kubectl-audit",
		Short:         "Kubernetes security audit: VAP/CEL policy checks, RBAC least-privilege analysis, and multi-framework compliance (CIS, FSTEC, NSA/CISA).",
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	// The only flag every subcommand genuinely shares: which audit.yaml to
	// read (some subcommands, like `version`, ignore it entirely, but a
	// stray --config there is harmless). Everything else is scoped to the
	// specific commands that actually use it — see addTargetFlags and
	// friends below — instead of being a blanket persistent flag every
	// leaf command's --help has to show regardless of relevance.
	root.PersistentFlags().StringVar(&flagConfig, "config", "", "path to audit.yaml (default: ~/.kubectl-audit/audit.yaml, if it exists)")
	// Also genuinely shared: every command hits the same diagnostic
	// call sites (warnf/debugf in orchestrate.go) regardless of which
	// leaf command runs. Debug-level detail is off by default (see
	// internal/logging) — this surfaces it: per-kind cluster fetch
	// outcomes, third-party CRD-group resolution, control-plane
	// container-matching misses, and similar decisions that are silent
	// otherwise. warning: lines already show unconditionally.
	root.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "show debug-level diagnostic detail (per-kind fetch outcomes, CRD resolution, heuristic misses) in addition to warnings")

	root.AddCommand(newScanCmd())
	root.AddCommand(newPolicyCmd())
	root.AddCommand(newRBACCmd())
	root.AddCommand(newTemplateCmd())
	root.AddCommand(newInspectCmd())
	root.AddCommand(newPushCmd())
	root.AddCommand(newVersionCmd("kubectl-audit"))
	return root
}

// addTargetFlags registers flags that select what to audit: cluster
// connection, static files, and namespace scoping. Shared by every command
// that calls loadResources (scan, rbac analyze).
func addTargetFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&flagContextName, "context", "", "kube context to use in cluster mode (default: current context)")
	f.StringVar(&flagClusterName, "cluster-name", "", "human-readable cluster name to use in the report's Target field and every finding's Source, instead of the raw kube-context name (e.g. \"prod-eu-west-1\"); doesn't change what's scanned. Also scopes every finding's ID (see findings.json's \"id\" field) so the same resource/policy pair in two different clusters never collides — set this consistently per cluster if you aggregate findings.json/triage state from more than one cluster")
	f.StringVar(&flagKubeconfig, "kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
	f.StringVar(&flagMode, "mode", "", "target mode: cluster|static|both (default: from config, or \"static\" if -f is set)")
	f.StringArrayVarP(&flagFiles, "filename", "f", nil, "static manifest file or directory to audit (repeatable) — matches kubectl apply's -f/--filename")
	f.StringArrayVarP(&flagNamespaces, "namespace", "n", nil, "namespace to scan in cluster mode (repeatable; default: all)")
	f.BoolVarP(&flagAllNamespaces, "all-namespaces", "A", false, "scan all namespaces in cluster mode")
	f.StringArrayVar(&flagExcludeNamespaces, "exclude-namespace", nil, "namespace to exclude (repeatable; default: kube-public, kube-node-lease). Pass an empty string to clear the defaults.")
	f.BoolVar(&flagIncludeSystemRBAC, "include-system-rbac", false, "include Role/ClusterRole/*Binding objects with the reserved \"system:\" prefix (Kubernetes built-ins), excluded by default")
	f.BoolVar(&flagNoBuiltinExceptions, "no-builtin-exceptions", false, "disable this tool's built-in exclusion rules for well-known, legitimately privileged infrastructure DaemonSets (Cilium's agent, prometheus-node-exporter, ...) — on by default; set this for a stricter scan showing literally everything, see docs")
	f.StringArrayVar(&flagDisableBuiltinExceptionIDs, "disable-builtin-exception-id", nil, "disable one built-in exclusion rule by its id (repeatable; see internal/suppress/builtin-exclusions.yaml for ids), leaving the rest active — finer-grained than --no-builtin-exceptions")
	f.StringVar(&flagRequestTimeout, "request-timeout", "", "per-request timeout for every call to the apiserver, as a Go duration (e.g. \"60s\", \"5m\") — bounds a hung (not just unreachable) apiserver from blocking the scan forever; \"0\" disables it entirely (default: from config, \"120s\")")
}

// addOutputFlags registers flags for where/how results get written. Shared
// by every command that calls writeOutputs (scan, rbac analyze).
func addOutputFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringArrayVar(&flagOutputs, "output", nil, "where to write a report format, as format=path (repeatable): json=findings.json, md=report.md, csv=findings.csv, confluence=report.conf, console=- (per-finding detail, grouped by check, with remediation — see --remediation), table=- (aggregate statistics: severity breakdown, per-check counts, compliance scorecard — not per-finding detail) — \"-\" means stdout, e.g. for a CI job log; csv/confluence/console/table default to not written; json/md default to \"findings.json\"/\"report.md\" (or \"rbac-findings.json\"/\"rbac-report.md\" for rbac analyze) unless overridden here or in config")
	f.BoolVar(&flagShowRemediation, "remediation", true, "include each check's remediation guidance in --output console=... (resolved through the same knowledge base report.md's Remediation column uses — Russian by default). On by default; set false to omit")
	f.StringVar(&flagFailOn, "fail-on", "", "minimum severity that causes a non-zero exit: none|low|medium|high|critical (default: from config, \"high\")")
	f.StringVar(&flagMinSeverity, "min-severity", "", "minimum severity rendered into findings.json/report.md/CSV/Confluence/console — a display filter only, doesn't affect --fail-on or compliance scorecards (which always see every finding): none|low|medium|high|critical (default: from config, \"none\" — render everything)")
	f.StringVar(&flagReportTemplate, "report-template", "", "path to a custom report.md.tpl (Go text/template); default uses the built-in template (see 'kubectl-audit template dump')")
	f.StringVar(&flagConfluenceTemplate, "confluence-template", "", "path to a custom confluence.tpl (Go text/template) for --output confluence=...; default uses the built-in Confluence wiki-markup template")
	f.StringVar(&flagReportLang, "report-lang", "", "language for the built-in Markdown report template: en|ru (default: from config, \"en\"). Ignored when --report-template is set.")
	f.StringVar(&flagOwner, "owner", "", "who's responsible for this report — shown in the report header; if it's a Jira username, triage also assigns every created issue to it (default: not shown, no auto-assignment)")
	f.StringVar(&flagReportView, "report-view", "", "how the Markdown report's Findings section is structured: check|namespace|both (default: from config, \"check\"). \"both\" lists every finding twice (once per view) — use \"check\" or \"namespace\" alone on large reports to avoid that duplication.")
	f.IntVar(&flagNamespaceGroupThreshold, "namespace-group-threshold", 0, "collapse a check's affected-resources list when the same Kind/Name pair repeats identically across at least this many namespaces (the common per-tenant-namespace shape, e.g. Capsule) — default: from config, 3. Set 0 to disable collapsing and always list every namespace individually.")
	f.BoolVar(&flagGroupByNamePattern, "group-by-name-pattern", true, "extend --namespace-group-threshold collapsing to names that share a generated-identifier shape (a UUID, or another long hex/digit run), not just an identical literal name — catches e.g. per-tenant Namespace objects themselves named \"usersvs-<uuid>\", which can never share a literal name since Namespace is cluster-scoped. On by default; set false to only collapse exact name matches.")
}

// addPolicyDirFlag registers --policy-dir on commands that load VAP
// policies (scan, policy list) — not rbac analyze, which never touches the
// policy engine at all.
func addPolicyDirFlag(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&flagPolicyDirs, "policy-dir", nil, "additional policy directory to load (repeatable)")
}

// addFrameworksFlag registers --frameworks on scan only: rbac analyze
// explicitly disables compliance scoring, so offering the flag there would
// silently do nothing.
func addFrameworksFlag(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&flagFrameworks, "frameworks", nil, "compliance framework(s) to score against: cis|fstec|nsa|capsule, or a path to a custom mapping YAML (repeatable or comma-separated; default: from config, \"cis\")")
	cmd.Flags().BoolVar(&flagFrameworksOnly, "frameworks-only", false, "drop every finding whose check isn't referenced (policyIds/nativeCheckIds) by at least one control in --frameworks, before scorecards/--fail-on/any output — scopes the audit strictly to the selected standard(s). Defaults to true whenever --frameworks is explicitly given (choosing a standard implies auditing against just that standard), false when it's left at its implicit \"cis\" default (full, unrestricted check set) — pass this explicitly (true or false) to override either direction")
}

// addCheckUpdatesFlag registers --check-updates on scan only: it's read by
// runScan, which rbac analyze deliberately bypasses.
func addCheckUpdatesFlag(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&flagCheckUpdates, "check-updates", false, "make a live request to endoflife.date to check the detected cluster version for available patch releases and real EOL/support status — the only network call this tool ever makes beyond the target cluster; off by default for air-gapped use")
}

// addReadSecretValuesFlag registers --read-secret-values on scan only.
// Off by default: a small number of checks (see docs/secrets-mode.md) can
// only tell "authentication is left at its documented default/disabled
// value" by looking at a Secret's actual content, which this tool
// otherwise never reads. Setting this both fetches Secrets (cluster mode)
// and lets any -f manifest's Secret objects reach policy evaluation
// (static mode) — and needs the elevated ClusterRole in
// rbac/clusterrole-with-secrets.yaml, not the default read-only one.
func addReadSecretValuesFlag(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&flagReadSecretValues, "read-secret-values", false, "let this scan read Secret values, to run checks that can only detect a default/disabled authentication value that way — off by default; needs rbac/clusterrole-with-secrets.yaml, not the default ClusterRole; see docs/secrets-mode.md")
}
