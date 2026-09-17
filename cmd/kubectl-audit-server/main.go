// Command kubectl-audit-server runs the multi-cluster aggregation server:
// clusters push findings.json scans to it, which are deduplicated and
// stored in Postgres for cross-cluster triage — see the architecture plan
// for the full design. This is phase 2's skeleton: registration + native
// ingestion only; triage/automation endpoints land in later phases.
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

	srv := api.NewServer(store, store, adminToken)
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
