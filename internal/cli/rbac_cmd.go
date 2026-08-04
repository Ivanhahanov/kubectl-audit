package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivanhahanov/kubectl-audit/internal/rbac"
	"github.com/ivanhahanov/kubectl-audit/internal/report"
)

func newRBACCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rbac",
		Short: "RBAC role-model and least-privilege analysis.",
	}
	cmd.AddCommand(newRBACAnalyzeCmd())
	return cmd
}

func newRBACAnalyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Build the effective RBAC role model and report least-privilege violations, without running workload policies.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadEffectiveConfig(cmd)
			if err != nil {
				return err
			}
			cfg.Compliance.Frameworks = nil

			resources, _, target, _, err := loadResources(cmd.Context(), cfg)
			if err != nil {
				return err
			}

			rbacResult, err := rbac.Analyze(resources, target, cfg.Target.IncludeSystemRBAC)
			if err != nil {
				return err
			}

			result := report.Result{
				GeneratedAt: time.Now(),
				Target:      target,
				Findings:    rbacResult.Findings,
				RBACModel:   rbacResult.Model,
			}

			if err := writeOutputs(cfg, result); err != nil {
				return err
			}

			fmt.Printf("Analyzed RBAC for %s — %d subject(s), %d finding(s)\n", target, len(rbacResult.Model), len(rbacResult.Findings))
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
	addTargetFlags(cmd)
	addOutputFlags(cmd)
	return cmd
}
