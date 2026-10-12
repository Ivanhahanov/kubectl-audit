package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is set via -ldflags at release build time (see Makefile).
var Version = "dev"

func newVersionCmd(toolName string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the " + toolName + " version.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(toolName + " " + Version)
			return nil
		},
	}
}
