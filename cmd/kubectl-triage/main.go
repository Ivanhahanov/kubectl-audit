// Command kubectl-triage is a kubectl plugin (`kubectl triage ...`, or run
// directly as `kubectl-triage ...`) for reviewing a kubectl-audit scan's
// findings.json: an interactive TUI for recording
// confirmed/false-positive/won't-fix decisions, non-interactive export, and
// Jira issue sync. Deliberately a separate binary from kubectl-audit so a
// self-service/CI user auditing a cluster never pulls in this tool's TUI
// (tcell/tview) and Jira-client dependencies.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ivanhahanov/kubectl-audit/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := cli.NewTriageRootCmd()
	root.SetContext(ctx)

	if err := root.Execute(); err != nil {
		os.Exit(2)
	}
}
