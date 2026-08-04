// Package cli implements the kubectl-audit command surface.
package cli

import (
	"github.com/spf13/cobra"
)

var (
	flagConfig            string
	flagContextName       string
	flagKubeconfig        string
	flagMode              string
	flagFiles             []string
	flagNamespaces        []string
	flagAllNamespaces     bool
	flagExcludeNamespaces []string
	flagIncludeSystemRBAC bool
	flagCheckUpdates      bool
	flagPolicyDirs        []string
	flagOutputJSON        string
	flagOutputMD          string
	flagFailOn            string
	flagFrameworks        []string
	flagReportTemplate    string
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
	root.PersistentFlags().StringVar(&flagConfig, "config", "", "path to audit.yaml")

	root.AddCommand(newScanCmd())
	root.AddCommand(newPolicyCmd())
	root.AddCommand(newRBACCmd())
	root.AddCommand(newTemplateCmd())
	root.AddCommand(newVersionCmd())
	return root
}

// addTargetFlags registers flags that select what to audit: cluster
// connection, static files, and namespace scoping. Shared by every command
// that calls loadResources (scan, rbac analyze).
func addTargetFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&flagContextName, "context", "", "kube context to use in cluster mode (default: current context)")
	f.StringVar(&flagKubeconfig, "kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
	f.StringVar(&flagMode, "mode", "", "target mode: cluster|static|both (default: from config, or \"static\" if -f is set)")
	f.StringArrayVarP(&flagFiles, "filename", "f", nil, "static manifest file or directory to audit (repeatable) — matches kubectl apply's -f/--filename")
	f.StringArrayVarP(&flagNamespaces, "namespace", "n", nil, "namespace to scan in cluster mode (repeatable; default: all)")
	f.BoolVarP(&flagAllNamespaces, "all-namespaces", "A", false, "scan all namespaces in cluster mode")
	f.StringArrayVar(&flagExcludeNamespaces, "exclude-namespace", nil, "namespace to exclude (repeatable; default: kube-system, kube-public, kube-node-lease). Pass an empty string to clear the defaults.")
	f.BoolVar(&flagIncludeSystemRBAC, "include-system-rbac", false, "include Role/ClusterRole/*Binding objects with the reserved \"system:\" prefix (Kubernetes built-ins), excluded by default")
}

// addOutputFlags registers flags for where/how results get written. Shared
// by every command that calls writeOutputs (scan, rbac analyze).
func addOutputFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&flagOutputJSON, "output-json", "", "path to write findings.json (default: from config, \"findings.json\")")
	f.StringVar(&flagOutputMD, "output-md", "", "path to write report.md (default: from config, \"report.md\")")
	f.StringVar(&flagFailOn, "fail-on", "", "minimum severity that causes a non-zero exit: none|low|medium|high|critical (default: from config, \"high\")")
	f.StringVar(&flagReportTemplate, "report-template", "", "path to a custom report.md.tpl (Go text/template); default uses the built-in template (see 'kubectl-audit template dump')")
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
	cmd.Flags().StringArrayVar(&flagFrameworks, "frameworks", nil, "compliance framework(s) to score against: cis|fstec|nsa, or a path to a custom mapping YAML (repeatable or comma-separated; default: from config, \"cis\")")
}

// addCheckUpdatesFlag registers --check-updates on scan only: it's read by
// runScan, which rbac analyze deliberately bypasses.
func addCheckUpdatesFlag(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&flagCheckUpdates, "check-updates", false, "make a live request to endoflife.date to check the detected cluster version for available patch releases and real EOL/support status — the only network call this tool ever makes beyond the target cluster; off by default for air-gapped use")
}
