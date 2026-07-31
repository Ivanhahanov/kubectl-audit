package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Audit a live cluster and/or static manifests: run policy checks, RBAC least-privilege analysis, and (optionally) the CIS Benchmark scorecard.",
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
			if cfg.Output.JSON != "" {
				fmt.Printf("Findings written to %s\n", cfg.Output.JSON)
			}
			if cfg.Output.Markdown != "" {
				fmt.Printf("Report written to %s\n", cfg.Output.Markdown)
			}

			applyFailOnGate(cfg, result)
			return nil
		},
	}
	return cmd
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
