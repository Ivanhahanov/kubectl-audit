package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivanhahanov/kubectl-audit/internal/compliance"
)

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Audit a live cluster and/or static manifests: policy checks, RBAC least-privilege analysis, NetworkPolicy coverage, Pod Security Standards, and compliance scorecards (--frameworks cis,fstec,nsa).",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadEffectiveConfig(cmd)
			if err != nil {
				return err
			}

			result, err := runScan(cmd.Context(), cfg)
			if err != nil {
				return err
			}

			if err := writeOutputs(cfg, result); err != nil {
				return err
			}

			summary := result.Summary()
			fmt.Printf("Scanned %s — %d polic%s loaded, %d finding(s): critical=%d high=%d medium=%d low=%d info=%d\n",
				result.Target, result.PoliciesLoaded, plural(result.PoliciesLoaded, "y", "ies"), len(result.Findings),
				summary["CRITICAL"], summary["HIGH"], summary["MEDIUM"], summary["LOW"], summary["INFO"])
			for _, s := range compliance.Summarize(result.Frameworks) {
				fmt.Printf("%s (%s) v%s — pass=%d fail=%d not_applicable=%d not_implemented=%d\n",
					s.Title, s.ID, s.Version, s.Pass, s.Fail, s.NotApplicable, s.NotImplemented)
			}
			if cfg.Output.JSON != "" {
				fmt.Printf("Findings written to %s\n", cfg.Output.JSON)
			}
			if cfg.Output.Markdown != "" {
				fmt.Printf("Report written to %s\n", cfg.Output.Markdown)
			}
			if cfg.Output.CSV != "" {
				fmt.Printf("Findings written to %s (CSV)\n", cfg.Output.CSV)
			}

			applyFailOnGate(cfg, result)
			return nil
		},
	}
	addTargetFlags(cmd)
	addPolicyDirFlag(cmd)
	addFrameworksFlag(cmd)
	addCheckUpdatesFlag(cmd)
	addOutputFlags(cmd)
	return cmd
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
