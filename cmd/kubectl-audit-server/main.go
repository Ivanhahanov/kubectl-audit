// Command kubectl-audit-server runs the multi-cluster aggregation server:
// clusters push findings.json scans to it, which are deduplicated and
// stored in Postgres for cross-cluster triage, centralized knowledge
// base/exclusion rules, and automation rule evaluation — see the
// architecture plan for the full design.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/server/automation"
	api "github.com/ivanhahanov/kubectl-audit/internal/server/http"
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
	adminToken := os.Getenv("ADMIN_TOKEN")
	if adminToken == "" {
		return errors.New("ADMIN_TOKEN is required")
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
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
		// LogTrigger/LogExecutor are the only implementations available
		// today — see their doc comments for why real Jira filing/agent
		// invocation/Tekton triggering aren't wired up yet.
		Executor: automation.LogExecutor{},
	}
	trigger := automation.LogTrigger{}

	srv := api.NewServer(api.Repos{
		Clusters:        store,
		Findings:        store,
		Triage:          store,
		KnowledgeBase:   store,
		ExclusionRules:  store,
		AutomationRules: store,
		AuditRequests:   store,
	}, adminToken, runner, trigger)
	httpServer := &http.Server{
		Addr:    addr,
		Handler: srv.Routes(),
	}

	go runAutomationTicker(ctx, runner, evaluationInterval)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("kubectl-audit-server listening on %s", addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("serving: %w", err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

// runAutomationTicker evaluates automation rules on a fixed interval —
// the always-on counterpart to POST /api/v1/automation-rules/evaluate
// (which runs one pass on demand, e.g. for a demo or a manual check).
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
