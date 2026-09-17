package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

const auditRequestColumns = `id, cluster_id, requested_by, reason, status, tekton_pipelinerun_name, scheduled_cron, created_at`

func scanAuditRequest(row pgx.Row) (storage.AuditRequest, error) {
	var r storage.AuditRequest
	err := row.Scan(&r.ID, &r.ClusterID, &r.RequestedBy, &r.Reason, &r.Status, &r.TektonPipelineRunName, &r.ScheduledCron, &r.CreatedAt)
	return r, err
}

func (s *Store) CreateAuditRequest(ctx context.Context, req storage.AuditRequest) (storage.AuditRequest, error) {
	status := req.Status
	if status == "" {
		status = storage.AuditRequestPending
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO audit_requests (cluster_id, requested_by, reason, status, scheduled_cron)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+auditRequestColumns,
		req.ClusterID, req.RequestedBy, req.Reason, status, req.ScheduledCron,
	)
	out, err := scanAuditRequest(row)
	if err != nil {
		return storage.AuditRequest{}, fmt.Errorf("creating audit request: %w", err)
	}
	return out, nil
}

func (s *Store) GetAuditRequest(ctx context.Context, id uuid.UUID) (storage.AuditRequest, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+auditRequestColumns+` FROM audit_requests WHERE id = $1`, id)
	out, err := scanAuditRequest(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.AuditRequest{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.AuditRequest{}, fmt.Errorf("looking up audit request: %w", err)
	}
	return out, nil
}

func (s *Store) ListAuditRequests(ctx context.Context, clusterID *uuid.UUID) ([]storage.AuditRequest, error) {
	query := `SELECT ` + auditRequestColumns + ` FROM audit_requests`
	var args []any
	if clusterID != nil {
		query += ` WHERE cluster_id = $1`
		args = append(args, *clusterID)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing audit requests: %w", err)
	}
	defer rows.Close()

	var out []storage.AuditRequest
	for rows.Next() {
		r, err := scanAuditRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning audit request row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) UpdateAuditRequest(ctx context.Context, req storage.AuditRequest) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE audit_requests SET status = $2, tekton_pipelinerun_name = $3, scheduled_cron = $4 WHERE id = $1
	`, req.ID, req.Status, req.TektonPipelineRunName, req.ScheduledCron)
	if err != nil {
		return fmt.Errorf("updating audit request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}
