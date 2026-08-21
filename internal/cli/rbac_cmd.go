package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivanhahanov/kubectl-audit/internal/rbac"
	"github.com/ivanhahanov/kubectl-audit/internal/report"
	"github.com/ivanhahanov/kubectl-audit/internal/suppress"
	"github.com/ivanhahanov/kubectl-audit/internal/thirdparty"
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

			// rbac analyze writes its own report by default, distinct from
			// scan's report.md/findings.json — otherwise running both
			// commands against the same directory silently overwrites one
			// report with the other. Only kicks in when the user didn't
			// pass --output-json/--output-md or set output.json/markdown
			// explicitly in audit.yaml to something other than scan's
			// defaults.
			if flagOutputJSON == "" && cfg.Output.JSON == "findings.json" {
				cfg.Output.JSON = "rbac-findings.json"
			}
			if flagOutputMD == "" && cfg.Output.Markdown == "report.md" {
				cfg.Output.Markdown = "rbac-report.md"
			}

			resources, unfiltered, target, _, err := loadResources(cmd.Context(), cfg)
			if err != nil {
				return err
			}

			rbacResult, err := rbac.Analyze(resources, target, cfg.Target.IncludeSystemRBAC)
			if err != nil {
				return err
			}

			kept, suppressed := suppress.Apply(rbacResult.Findings, effectiveExclusions(cfg), suppress.BuildLabelIndex(unfiltered))
			detected := thirdparty.Detect(unfiltered, effectiveComponents(cfg))

			result := report.Result{
				GeneratedAt:             time.Now(),
				Target:                  target,
				Findings:                kept,
				Suppressed:              toReportSuppressed(suppressed),
				RBACModel:               rbacResult.Model,
				ReportView:              cfg.Output.ReportView,
				MultipleSources:         hasMultipleSources(resources),
				DetectedComponents:      detected,
				NamespaceGroupThreshold: cfg.Output.NamespaceGroupThreshold,
			}

			if err := writeOutputs(cfg, result); err != nil {
				return err
			}

			fmt.Printf("Analyzed RBAC for %s — %d subject(s), %d finding(s)", target, len(rbacResult.Model), len(kept))
			if len(suppressed) > 0 {
				fmt.Printf(" (%d suppressed)", len(suppressed))
			}
			fmt.Println()
			if len(detected) > 0 {
				fmt.Println("Detected components:")
				for _, label := range detectedComponentLabels(detected) {
					fmt.Printf("  - %s\n", label)
				}
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
	addOutputFlags(cmd)
	return cmd
}
