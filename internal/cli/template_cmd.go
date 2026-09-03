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
	var format string
	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Write a built-in report template to disk, as a starting point for --report-template/--confluence-template customization.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var src string
			switch format {
			case "", "md":
				src = report.DefaultTemplate()
			case "ru":
				src = report.RussianTemplate()
			case "confluence":
				src = report.DefaultConfluenceTemplate()
			default:
				return fmt.Errorf("unknown --format %q: want md, ru, or confluence", format)
			}
			if out == "" {
				fmt.Print(src)
				return nil
			}
			if err := os.WriteFile(out, []byte(src), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", out, err)
			}
			fmt.Printf("Wrote %s template to %s\n", format, out)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "file to write (default: stdout)")
	cmd.Flags().StringVar(&format, "format", "md", "which built-in template to dump: md|ru|confluence")
	return cmd
}
