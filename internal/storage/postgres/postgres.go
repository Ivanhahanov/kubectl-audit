// Package postgres implements internal/storage's repository interfaces
// against a real Postgres database (via CloudNativePG in production —
// see the architecture plan — or any Postgres 14+ elsewhere). One Store
// type backs all three repo interfaces (ClusterRepo/FindingRepo/
// TriageRepo): a single connection pool is enough at this scale (push-
// based ingestion, not high-QPS telemetry — see the plan's rationale for
// not introducing a queue/broker), and callers depend on the
// internal/storage interfaces, not this concrete type, so nothing outside
// this package needs to know it's one struct instead of three.
package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	pgxmigrate "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver, used only for running migrations

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
	"github.com/ivanhahanov/kubectl-audit/internal/storage/migrations"
)

// Store implements internal/storage.ClusterRepo, FindingRepo, and
// TriageRepo against a pgxpool.Pool.
type Store struct {
	pool *pgxpool.Pool
}

var (
	_ storage.ClusterRepo        = (*Store)(nil)
	_ storage.FindingRepo        = (*Store)(nil)
	_ storage.TriageRepo         = (*Store)(nil)
	_ storage.KnowledgeBaseRepo  = (*Store)(nil)
	_ storage.ExclusionRuleRepo  = (*Store)(nil)
	_ storage.AutomationRuleRepo = (*Store)(nil)
	_ storage.AuditRequestRepo   = (*Store)(nil)
)

// Open connects to Postgres at dsn (a standard "postgres://..." URL —
// e.g. the connection string from CloudNativePG's own generated Secret in
// production) and runs any pending migrations before returning. Ping-tests
// the pool immediately so a misconfigured DSN fails at startup, not on the
// first request.
func Open(ctx context.Context, dsn string) (*Store, error) {
	if err := runMigrations(dsn); err != nil {
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the underlying connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// runMigrations applies every embedded migration up to the latest version.
// golang-migrate needs a database/sql connection (distinct from the
// pgxpool used for ordinary queries) purely to drive its own migration
// bookkeeping — opened and closed within this call, never kept around.
func runMigrations(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("opening migration connection: %w", err)
	}
	// Deliberately still deferred even though the pgx5 driver's own
	// Close() (called via m.Close() below, once construction succeeds)
	// closes this same *sql.DB too: sql.DB.Close() is a no-op once
	// already closed, and this covers the error path where WithInstance/
	// NewWithInstance fails below, before m.Close() is ever reached.
	defer db.Close()

	driver, err := pgxmigrate.WithInstance(db, &pgxmigrate.Config{})
	if err != nil {
		return fmt.Errorf("initializing migration driver: %w", err)
	}

	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("loading embedded migrations: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "pgx5", driver)
	if err != nil {
		return fmt.Errorf("initializing migrator: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}
	return nil
}
