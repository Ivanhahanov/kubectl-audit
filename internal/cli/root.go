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
	flagPolicyDirs        []string
	flagOutputJSON        string
	flagOutputMD          string
	flagFailOn            string
	flagCIS               bool
)

// NewRootCmd builds the kubectl-audit command tree.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "kubectl-audit",
		Short:         "Kubernetes security audit: VAP/CEL policy checks, RBAC least-privilege analysis, and CIS Benchmark compliance.",
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	pf := root.PersistentFlags()
	pf.StringVar(&flagConfig, "config", "", "path to audit.yaml")
	pf.StringVar(&flagContextName, "context", "", "kube context to use in cluster mode (default: current context)")
	pf.StringVar(&flagKubeconfig, "kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
	pf.StringVar(&flagMode, "mode", "", "target mode: cluster|static|both (default: from config, or \"static\" if -f is set)")
	pf.StringArrayVarP(&flagFiles, "files", "f", nil, "static manifest file or directory to audit (repeatable)")
	pf.StringArrayVarP(&flagNamespaces, "namespace", "n", nil, "namespace to scan in cluster mode (repeatable; default: all)")
	pf.BoolVar(&flagAllNamespaces, "all-namespaces", false, "scan all namespaces in cluster mode")
	pf.StringArrayVar(&flagExcludeNamespaces, "exclude-namespace", nil, "namespace to exclude (repeatable; default: kube-system, kube-public, kube-node-lease). Pass an empty string to clear the defaults.")
	pf.BoolVar(&flagIncludeSystemRBAC, "include-system-rbac", false, "include Role/ClusterRole/*Binding objects with the reserved \"system:\" prefix (Kubernetes built-ins), excluded by default")
	pf.StringArrayVar(&flagPolicyDirs, "policy-dir", nil, "additional policy directory to load (repeatable)")
	pf.StringVar(&flagOutputJSON, "output-json", "", "path to write findings.json (default: from config, \"findings.json\")")
	pf.StringVar(&flagOutputMD, "output-md", "", "path to write report.md (default: from config, \"report.md\")")
	pf.StringVar(&flagFailOn, "fail-on", "", "minimum severity that causes a non-zero exit: none|low|medium|high|critical (default: from config, \"high\")")
	pf.BoolVar(&flagCIS, "cis", false, "force-enable the CIS Benchmark scorecard")

	root.AddCommand(newScanCmd())
	root.AddCommand(newPolicyCmd())
	root.AddCommand(newRBACCmd())
	root.AddCommand(newCISCmd())
	root.AddCommand(newVersionCmd())
	return root
}
