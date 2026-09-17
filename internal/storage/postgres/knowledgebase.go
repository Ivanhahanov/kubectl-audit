package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

func (s *Store) GetKnowledgeBaseEntry(ctx context.Context, policyID string) (storage.KnowledgeBaseEntry, error) {
	var e storage.KnowledgeBaseEntry
	err := s.pool.QueryRow(ctx, `
		SELECT policy_id, title, category, description, remediation, labels, updated_at
		FROM knowledge_base_entries WHERE policy_id = $1
	`, policyID).Scan(&e.PolicyID, &e.Title, &e.Category, &e.Description, &e.Remediation, &e.Labels, &e.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.KnowledgeBaseEntry{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.KnowledgeBaseEntry{}, fmt.Errorf("looking up knowledge base entry: %w", err)
	}
	return e, nil
}

// PutKnowledgeBaseEntry implements storage.KnowledgeBaseRepo.PutKnowledgeBaseEntry.
func (s *Store) PutKnowledgeBaseEntry(ctx context.Context, entry storage.KnowledgeBaseEntry) error {
	labels := entry.Labels
	if labels == nil {
		// Same nil-slice-to-Postgres-array pitfall as findings.cis (see
		// IngestScan's comment) — every column is always specified here,
		// so the column's own DEFAULT '{}' never applies.
		labels = []string{}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO knowledge_base_entries (policy_id, title, category, description, remediation, labels, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, now())
		ON CONFLICT (policy_id) DO UPDATE SET
			title       = EXCLUDED.title,
			category    = EXCLUDED.category,
			description = EXCLUDED.description,
			remediation = EXCLUDED.remediation,
			labels      = EXCLUDED.labels,
			updated_at  = now()
	`, entry.PolicyID, entry.Title, entry.Category, entry.Description, entry.Remediation, labels)
	if err != nil {
		return fmt.Errorf("saving knowledge base entry: %w", err)
	}
	return nil
}
