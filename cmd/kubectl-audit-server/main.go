// Command kubectl-audit-server runs the multi-cluster aggregation server:
// clusters push findings.json scans to it, which are deduplicated and
// stored in Postgres for cross-cluster triage, centralized knowledge
// base/exclusion rules, and automation rule evaluation — see the
// architecture plan for the full design. The recurring automation
// evaluation loop itself lives in cmd/kubectl-audit-worker, not here — this
// binary only exposes an on-demand admin trigger for it
// (POST /automation-rules/evaluate); see that command's doc comment for why
// it's a separate process.
//
//	@title			kubectl-audit-server API
//	@version		1.0
//	@description	Multi-cluster aggregation server for kubectl-audit: clusters push findings.json scans here, which are deduplicated and stored for cross-cluster triage, centralized knowledge base/exclusion rules, and automation rule evaluation.
//
//	@license.name	Apache 2.0
//	@license.url	https://www.apache.org/licenses/LICENSE-2.0.html
//
//	@BasePath	/api/v1
//
//	@securityDefinitions.apikey	AdminAuth
//	@in							header
//	@name						Authorization
//	@description				Admin bearer token (env ADMIN_TOKEN). Send as "Bearer <token>". Required for cluster registration and every organization-level config endpoint (knowledge base, exclusion rules, automation rules, triage).
//
//	@securityDefinitions.apikey	ClusterAuth
//	@in							header
//	@name						Authorization
//	@description				Per-cluster bearer token minted by POST /clusters. Send as "Bearer <token>". Required for ingest endpoints only — scoped to that cluster's own data, and does not grant triage read/write (see AdminAuth).
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/ivanhahanov/kubectl-audit/cmd/kubectl-audit-server/docs"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer store.Close()

	// Only used for the on-demand POST /automation-rules/evaluate path —
	// the recurring ticker lives in cmd/kubectl-audit-worker, a separate
	// process against the same database (Evaluator reads fresh state per
	// call, so two processes each owning their own Runner need no
	// coordination).
	runner := &automation.Runner{
		Clusters:  store,
		Evaluator: &automation.Evaluator{Rules: store, Findings: store, Triage: store},
		Executor:  automation.LogExecutor{},
	}

	srv := api.NewServer(api.Repos{
		Clusters:        store,
		Findings:        store,
		Triage:          store,
		KnowledgeBase:   store,
		ExclusionRules:  store,
		AutomationRules: store,
	}, adminToken, runner)
	httpServer := &http.Server{
		Addr:    addr,
		Handler: srv.Routes(),
	}

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
