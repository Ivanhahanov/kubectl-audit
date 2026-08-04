package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ivanhahanov/kubectl-audit/internal/report"
)

func newTemplateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Report template utilities.",
	}
	cmd.AddCommand(newTemplateDumpCmd())
	return cmd
}

func newTemplateDumpCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Write the built-in report.md.tpl to disk, as a starting point for --report-template customization.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				fmt.Print(report.DefaultTemplate())
				return nil
			}
			if err := os.WriteFile(out, []byte(report.DefaultTemplate()), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", out, err)
			}
			fmt.Printf("Wrote default template to %s\n", out)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "file to write (default: stdout)")
	return cmd
}
