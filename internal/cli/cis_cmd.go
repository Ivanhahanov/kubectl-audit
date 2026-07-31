package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivanhahanov/kubectl-audit/internal/cis"
)

func newCISCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cis",
		Short: "CIS Kubernetes Benchmark compliance.",
	}
	cmd.AddCommand(newCISReportCmd())
	return cmd
}

func newCISReportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "report",
		Short: "Run a full scan and report CIS Kubernetes Benchmark compliance (control-plane/node sections are marked Not Applicable).",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadEffectiveConfig(cmd)
			if err != nil {
				return err
			}
			cfg.CIS.Enabled = true

			result, err := runScan(cmd.Context(), cfg)
			if err != nil {
				return err
			}

			if err := writeOutputs(cfg, result); err != nil {
				return err
			}

			var pass, fail, na, ni int
			for _, res := range result.CIS.Results {
				switch res.Status {
				case cis.StatusPass:
					pass++
				case cis.StatusFail:
					fail++
				case cis.StatusNotApplicable:
					na++
				case cis.StatusNotImplemented:
					ni++
				}
			}
			fmt.Printf("CIS Kubernetes Benchmark v%s — pass=%d fail=%d not_applicable=%d not_implemented=%d\n",
				result.CIS.Version, pass, fail, na, ni)
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
}
