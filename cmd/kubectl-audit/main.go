// Command kubectl-audit is a kubectl plugin (`kubectl audit ...`) that runs
// a production Kubernetes security audit: VAP/CEL policy checks against
// live cluster and/or static manifests, RBAC least-privilege analysis, and
// CIS Kubernetes Benchmark compliance reporting.
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

	root := cli.NewRootCmd()
	root.SetContext(ctx)

	if err := root.Execute(); err != nil {
		os.Exit(2)
	}
}
