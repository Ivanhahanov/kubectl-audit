// Command kubectl-audit-worker runs the recurring automation-rule
// evaluation loop against kubectl-audit-server's database — AI-assisted
// triage enrichment, ticket-worthy-finding detection, etc. (see
// automation.ActionExecutor's implementations) as they're built out.
//
// This is a separate process/deployment from kubectl-audit-server on
// purpose: an ActionExecutor that calls out to an LLM or Jira is slow and
// depends on external APIs that can be down or rate-limited, and a panic in
// one unrecovered goroutine crashes the whole Go process — none of that
// should be able to take down the ingest API that scanners depend on being
// fast and always up. Splitting them means each can be deployed/scaled/
// restarted independently, and a bug in triage logic has no blast radius on
// ingest. Coordination is just "read the same Postgres" — no separate queue
// needed at this scale (kubectl-audit-server also runs one-off evaluations
// on demand via POST /automation-rules/evaluate; both are just callers of
// the same automation.Runner, and don't need to coordinate with each other
// since Evaluator always reads current state fresh).
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/server/automation"
	"github.com/ivanhahanov/kubectl-audit/internal/storage/postgres"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}
	evaluationInterval := 5 * time.Minute
	if raw := os.Getenv("AUTOMATION_INTERVAL_SECONDS"); raw != "" {
		secs, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("invalid AUTOMATION_INTERVAL_SECONDS: %w", err)
		}
		evaluationInterval = time.Duration(secs) * time.Second
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer store.Close()

	runner := &automation.Runner{
		Clusters:  store,
		Evaluator: &automation.Evaluator{Rules: store, Findings: store, Triage: store},
		// LogExecutor is the only implementation available today — see its
		// doc comment for why real Jira filing/agent invocation aren't
		// wired up yet.
		Executor: automation.LogExecutor{},
	}

	log.Printf("kubectl-audit-worker evaluating every %s", evaluationInterval)
	runAutomationTicker(ctx, runner, evaluationInterval)
	return nil
}

// runAutomationTicker evaluates automation rules on a fixed interval until
// ctx is cancelled.
func runAutomationTicker(ctx context.Context, runner *automation.Runner, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := runner.RunOnce(ctx); err != nil {
				log.Printf("automation evaluation failed: %v", err)
			}
		}
	}
}
