package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

// Register inserts a new cluster row. name must be unique — a duplicate
// name surfaces as a plain wrapped error (the caller layer, not this
// repo, decides whether that maps to an HTTP 409).
func (s *Store) Register(ctx context.Context, name, endpoint, owner, tokenHash string) (storage.Cluster, error) {
	var c storage.Cluster
	err := s.pool.QueryRow(ctx, `
		INSERT INTO clusters (name, endpoint, owner, token_hash)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, endpoint, owner, token_hash, created_at
	`, name, endpoint, owner, tokenHash).Scan(&c.ID, &c.Name, &c.Endpoint, &c.Owner, &c.TokenHash, &c.CreatedAt)
	if err != nil {
		return storage.Cluster{}, fmt.Errorf("registering cluster %q: %w", name, err)
	}
	return c, nil
}

func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (storage.Cluster, error) {
	return s.scanCluster(ctx, `
		SELECT id, name, endpoint, owner, token_hash, created_at FROM clusters WHERE id = $1
	`, id)
}

func (s *Store) GetByTokenHash(ctx context.Context, tokenHash string) (storage.Cluster, error) {
	return s.scanCluster(ctx, `
		SELECT id, name, endpoint, owner, token_hash, created_at FROM clusters WHERE token_hash = $1
	`, tokenHash)
}

func (s *Store) scanCluster(ctx context.Context, query string, arg any) (storage.Cluster, error) {
	var c storage.Cluster
	err := s.pool.QueryRow(ctx, query, arg).Scan(&c.ID, &c.Name, &c.Endpoint, &c.Owner, &c.TokenHash, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.Cluster{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.Cluster{}, fmt.Errorf("looking up cluster: %w", err)
	}
	return c, nil
}

func (s *Store) ListClusters(ctx context.Context) ([]storage.Cluster, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, endpoint, owner, token_hash, created_at FROM clusters ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("listing clusters: %w", err)
	}
	defer rows.Close()

	var out []storage.Cluster
	for rows.Next() {
		var c storage.Cluster
		if err := rows.Scan(&c.ID, &c.Name, &c.Endpoint, &c.Owner, &c.TokenHash, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning cluster row: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
