package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

// GetTriageEntry implements storage.TriageRepo.GetTriageEntry — see its
// doc comment for why a missing entry is (zero value, false, nil), not an
// error.
func (s *Store) GetTriageEntry(ctx context.Context, clusterID uuid.UUID, source, fingerprint string) (storage.TriageEntry, bool, error) {
	var e storage.TriageEntry
	err := s.pool.QueryRow(ctx, `
		SELECT cluster_id, source, fingerprint, status, note, reviewer, jira_issue_key, jira_issue_url, updated_at
		FROM triage_entries WHERE cluster_id = $1 AND source = $2 AND fingerprint = $3
	`, clusterID, source, fingerprint).Scan(
		&e.ClusterID, &e.Source, &e.Fingerprint, &e.Status, &e.Note, &e.Reviewer,
		&e.JiraIssueKey, &e.JiraIssueURL, &e.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.TriageEntry{}, false, nil
	}
	if err != nil {
		return storage.TriageEntry{}, false, fmt.Errorf("looking up triage entry: %w", err)
	}
	return e, true, nil
}

// UpsertTriageEntry inserts or updates one triage decision. Note this does
// NOT enforce that a (cluster_id, source, fingerprint) finding already
// exists at the SQL level beyond the schema's own foreign key — callers
// (the future HTTP layer) are expected to have resolved the finding first
// via FindingRepo.GetFinding, the same way internal/triage.Merge always
// operates on a Row that already ties an Entry to a live/known Finding.
func (s *Store) UpsertTriageEntry(ctx context.Context, entry storage.TriageEntry) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO triage_entries (cluster_id, source, fingerprint, status, note, reviewer, jira_issue_key, jira_issue_url, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
		ON CONFLICT (cluster_id, source, fingerprint) DO UPDATE SET
			status         = EXCLUDED.status,
			note           = EXCLUDED.note,
			reviewer       = EXCLUDED.reviewer,
			jira_issue_key = EXCLUDED.jira_issue_key,
			jira_issue_url = EXCLUDED.jira_issue_url,
			updated_at     = now()
	`, entry.ClusterID, entry.Source, entry.Fingerprint, entry.Status, entry.Note, entry.Reviewer,
		entry.JiraIssueKey, entry.JiraIssueURL)
	if err != nil {
		return fmt.Errorf("upserting triage entry: %w", err)
	}
	return nil
}

func (s *Store) ListTriageEntries(ctx context.Context, clusterID uuid.UUID) ([]storage.TriageEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT cluster_id, source, fingerprint, status, note, reviewer, jira_issue_key, jira_issue_url, updated_at
		FROM triage_entries WHERE cluster_id = $1 ORDER BY updated_at DESC
	`, clusterID)
	if err != nil {
		return nil, fmt.Errorf("listing triage entries: %w", err)
	}
	defer rows.Close()

	var out []storage.TriageEntry
	for rows.Next() {
		var e storage.TriageEntry
		if err := rows.Scan(
			&e.ClusterID, &e.Source, &e.Fingerprint, &e.Status, &e.Note, &e.Reviewer,
			&e.JiraIssueKey, &e.JiraIssueURL, &e.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning triage entry row: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
