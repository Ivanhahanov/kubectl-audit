package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ivanhahanov/kubectl-audit/internal/engine"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Inspect and validate audit policies (real ValidatingAdmissionPolicy YAML).",
	}
	cmd.AddCommand(newPolicyValidateCmd())
	cmd.AddCommand(newPolicyListCmd())
	return cmd
}

func newPolicyValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <dir> [dir...]",
		Short: "Parse and CEL-compile every policy in the given directories, reporting every error found.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var failed bool
			var total int
			for _, dir := range args {
				policies, err := engine.LoadDir(dir)
				if err != nil {
					failed = true
					fmt.Fprintf(os.Stderr, "%v\n", err)
					continue
				}
				total += len(policies)
				for _, p := range policies {
					fmt.Printf("OK   %s (%s)\n", p.Meta.ID, dir)
				}
			}
			fmt.Printf("\n%d polic%s compiled successfully.\n", total, plural(total, "y", "ies"))
			if failed {
				return fmt.Errorf("one or more policies failed to compile")
			}
			return nil
		},
	}
}

func newPolicyListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List every policy that would be loaded for a scan (built-in + --policy-dir), with severity/category/CIS refs.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadEffectiveConfig(cmd)
			if err != nil {
				return err
			}
			policies, err := engine.LoadRegistry(cfg.Policies, nil)
			if err != nil {
				return err
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSEVERITY\tCATEGORY\tCIS")
			for _, p := range policies {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Meta.ID, p.Meta.Severity, p.Meta.Category, joinOrDash(p.Meta.CIS))
			}
			return w.Flush()
		},
	}
	addPolicyDirFlag(cmd)
	return cmd
}

func joinOrDash(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	out := items[0]
	for _, i := range items[1:] {
		out += "," + i
	}
	return out
}
