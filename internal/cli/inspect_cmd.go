package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivanhahanov/kubectl-audit/internal/k8sclient"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/rbac"
)

// inspect is a narrow, read-only diagnostic surface built entirely on
// existing, already-tested code (internal/loader/internal/rbac — the same
// paths `scan` itself uses), one object/subject at a time instead of a
// whole-cluster scan. Its primary purpose is the architecture plan's AI-
// agent integration design: an MCP adapter (see cmd/kubectl-audit-mcp)
// execs these commands as its only cluster-facing capability, so an agent
// never gets direct cluster access (no kubeconfig, no live API
// credentials) — see that command's doc comment. It's also just a useful
// standalone diagnostic for a human to run directly.
//
// Hard, unconditional rule (stricter than --read-secret-values elsewhere
// in this tool): these commands never return Secret values, under any
// flag — see loader.GetResource's own doc comment for where that's
// enforced.
var (
	flagInspectKubeconfig string
	flagInspectContext    string
	flagInspectNamespace  string
)

func newInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Narrow, read-only lookups against a live cluster: one resource, or one subject's RBAC chain.",
		Long: "Unlike `scan`, which audits an entire cluster and writes a report, `inspect` answers one " +
			"targeted question at a time and prints its JSON result to stdout — a diagnostic tool for a " +
			"human, and the only cluster-facing capability the MCP adapter (cmd/kubectl-audit-mcp) exposes " +
			"to an AI agent, which otherwise never gets direct cluster access. Secret objects can never be " +
			"inspected, under any flag.",
	}
	cmd.PersistentFlags().StringVar(&flagInspectKubeconfig, "kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
	cmd.PersistentFlags().StringVar(&flagInspectContext, "context", "", "kube context to use (default: current context)")
	cmd.AddCommand(newInspectResourceCmd())
	cmd.AddCommand(newInspectRBACChainCmd())
	return cmd
}

func newInspectResourceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "resource <kind>/<name>",
		Short: "Fetch one object by Kind/Name and print it as JSON.",
		Long:  "e.g. `kubectl-audit inspect resource Deployment/web -n default`. Secret objects are never supported, unconditionally.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, name, err := splitKindName(args[0])
			if err != nil {
				return err
			}
			client, err := k8sclient.New(flagInspectKubeconfig, flagInspectContext)
			if err != nil {
				return fmt.Errorf("connecting to cluster: %w", err)
			}
			res, err := loader.GetResource(cmd.Context(), client, kind, flagInspectNamespace, name)
			if err != nil {
				return err
			}
			return printJSON(res.Object)
		},
	}
	cmd.Flags().StringVarP(&flagInspectNamespace, "namespace", "n", "", "namespace (required for namespaced kinds)")
	return cmd
}

func newInspectRBACChainCmd() *cobra.Command {
	var subject, subjectNamespace string
	cmd := &cobra.Command{
		Use:   "rbac-chain --subject <kind>/<name>",
		Short: "Show one subject's effective RBAC bindings, permissions, and risk flags.",
		Long: "e.g. `kubectl-audit inspect rbac-chain --subject ServiceAccount/deploy-bot -n ci` or " +
			"`--subject Group/system:masters`. The same role-model data `rbac analyze`/`scan` compute for " +
			"every subject at once, on demand for just one — including built-in \"system:\" subjects, " +
			"which a default scan excludes as noise but an explicit lookup like this one doesn't.",
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, name, err := splitKindName(subject)
			if err != nil {
				return fmt.Errorf("--subject: %w", err)
			}

			client, err := k8sclient.New(flagInspectKubeconfig, flagInspectContext)
			if err != nil {
				return fmt.Errorf("connecting to cluster: %w", err)
			}
			resources, err := loader.LoadCluster(cmd.Context(), client, loader.ClusterOptions{
				AllNamespaces: true,
				IncludeKinds:  []string{"roles", "clusterroles", "rolebindings", "clusterrolebindings", "serviceaccounts"},
				Source:        loader.SourceLabel(flagInspectContext),
			})
			if err != nil {
				return fmt.Errorf("loading RBAC resources: %w", err)
			}

			// includeSystemSubjects: true — see the command's own Long
			// description for why an explicit, targeted lookup like this
			// one doesn't apply the same noise-reduction default a
			// whole-cluster scan does.
			result, err := rbac.Analyze(resources, loader.SourceLabel(flagInspectContext), true)
			if err != nil {
				return err
			}

			want := rbac.SubjectKey{Kind: kind, Namespace: subjectNamespace, Name: name}
			for _, m := range result.Model {
				if m.Subject == want {
					return printJSON(m)
				}
			}
			// No bindings found is a legitimate, non-error answer (e.g. a
			// ServiceAccount nobody bound a Role to yet) — the empty-slice
			// shape rather than a "not found" error keeps callers (the MCP
			// adapter especially) from needing a special case.
			return printJSON(rbac.SubjectModel{Subject: want})
		},
	}
	cmd.Flags().StringVar(&subject, "subject", "", "subject to look up, as <kind>/<name> — e.g. ServiceAccount/deploy-bot, Group/system:masters (required)")
	cmd.Flags().StringVarP(&subjectNamespace, "namespace", "n", "", "subject's namespace — only meaningful for ServiceAccount")
	cmd.MarkFlagRequired("subject")
	return cmd
}

func splitKindName(s string) (kind, name string, err error) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("expected <kind>/<name>, got %q", s)
	}
	return parts[0], parts[1], nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
