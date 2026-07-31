package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is set via -ldflags at release build time (see Makefile).
var Version = "dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the kubectl-audit version.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("kubectl-audit " + Version)
			return nil
		},
	}
}
