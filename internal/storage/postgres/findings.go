package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

// IngestScan implements storage.FindingRepo.IngestScan — see that
// interface's doc comment for the full contract (fingerprint upsert +
// per-source resolution, all in one transaction). Findings are upserted
// one at a time within the transaction, not batched: ingestion is
// push-based and infrequent (periodic scans, not high-QPS telemetry — see
// the architecture plan's rationale for skipping a queue/broker entirely),
// so a per-row round trip is not a real bottleneck at this scale; revisit
// with pgx.Batch only if a real ingestion volume proves otherwise.
func (s *Store) IngestScan(ctx context.Context, scan storage.Scan, findings []storage.Finding) (storage.Scan, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return storage.Scan{}, fmt.Errorf("beginning ingest transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	err = tx.QueryRow(ctx, `
		INSERT INTO scans (cluster_id, source, generated_at, cluster_version)
		VALUES ($1, $2, $3, $4)
		RETURNING id, cluster_id, source, generated_at, cluster_version, ingested_at
	`, scan.ClusterID, scan.Source, scan.GeneratedAt, scan.ClusterVersion).Scan(
		&scan.ID, &scan.ClusterID, &scan.Source, &scan.GeneratedAt, &scan.ClusterVersion, &scan.IngestedAt,
	)
	if err != nil {
		return storage.Scan{}, fmt.Errorf("recording scan: %w", err)
	}

	fingerprints := make([]string, 0, len(findings))
	for _, f := range findings {
		fingerprints = append(fingerprints, f.Fingerprint)
		properties, err := json.Marshal(f.Properties)
		if err != nil {
			return storage.Scan{}, fmt.Errorf("encoding properties for finding %s: %w", f.Fingerprint, err)
		}
		// cis's column is NOT NULL DEFAULT '{}', but that default only
		// applies when the column is omitted from the INSERT entirely —
		// since every column is always specified here, a nil Go slice
		// (the common case: most findings have no CIS mapping) would
		// otherwise be encoded as SQL NULL and violate the constraint,
		// not fall back to the column default.
		cis := f.CIS
		if cis == nil {
			cis = []string{}
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO findings (
				cluster_id, source, fingerprint, policy_id, title, severity, category, cis,
				resource_api_version, resource_kind, resource_namespace, resource_name,
				message, remediation, verification_steps, properties,
				first_seen, last_seen, last_scan_id
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$17,$18)
			ON CONFLICT (cluster_id, source, fingerprint) DO UPDATE SET
				policy_id            = EXCLUDED.policy_id,
				title                = EXCLUDED.title,
				severity             = EXCLUDED.severity,
				category             = EXCLUDED.category,
				cis                  = EXCLUDED.cis,
				resource_api_version = EXCLUDED.resource_api_version,
				resource_kind        = EXCLUDED.resource_kind,
				resource_namespace   = EXCLUDED.resource_namespace,
				resource_name        = EXCLUDED.resource_name,
				message              = EXCLUDED.message,
				remediation          = EXCLUDED.remediation,
				verification_steps   = EXCLUDED.verification_steps,
				properties           = EXCLUDED.properties,
				last_seen            = EXCLUDED.last_seen,
				last_scan_id         = EXCLUDED.last_scan_id
				-- first_seen intentionally NOT in the DO UPDATE SET list:
				-- an existing row keeps its original first_seen across
				-- every subsequent re-ingestion.
		`,
			scan.ClusterID, scan.Source, f.Fingerprint, f.PolicyID, f.Title, f.Severity, f.Category, cis,
			f.ResourceAPIVersion, f.ResourceKind, f.ResourceNamespace, f.ResourceName,
			f.Message, f.Remediation, f.VerificationSteps, properties,
			scan.GeneratedAt, scan.ID,
		)
		if err != nil {
			return storage.Scan{}, fmt.Errorf("upserting finding %s: %w", f.Fingerprint, err)
		}
	}

	// Resolution pass: any triage_entries row for this exact
	// (cluster_id, source) whose fingerprint is absent from the scan just
	// ingested is now resolved — scoped per-source deliberately, so an
	// OpenReports-sourced finding is never resolved just because a
	// kubectl-audit scan of the same cluster didn't mention it. Vacuously
	// resolves everything for this (cluster_id, source) when findings is
	// empty — Postgres' "<> ALL(empty array)" is true for any value,
	// which is the correct behavior here (an empty new scan means nothing
	// from that source was seen this time).
	_, err = tx.Exec(ctx, `
		UPDATE triage_entries
		SET status = 'resolved', updated_at = now()
		WHERE cluster_id = $1 AND source = $2 AND status <> 'resolved' AND fingerprint <> ALL($3::text[])
	`, scan.ClusterID, scan.Source, fingerprints)
	if err != nil {
		return storage.Scan{}, fmt.Errorf("resolving findings missing from this scan: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return storage.Scan{}, fmt.Errorf("committing ingest transaction: %w", err)
	}
	return scan, nil
}

const findingColumns = `
	cluster_id, source, fingerprint, policy_id, title, severity, category, cis,
	resource_api_version, resource_kind, resource_namespace, resource_name,
	message, remediation, verification_steps, properties,
	first_seen, last_seen, last_scan_id
`

func scanFinding(row pgx.Row) (storage.Finding, error) {
	var f storage.Finding
	var properties []byte
	err := row.Scan(
		&f.ClusterID, &f.Source, &f.Fingerprint, &f.PolicyID, &f.Title, &f.Severity, &f.Category, &f.CIS,
		&f.ResourceAPIVersion, &f.ResourceKind, &f.ResourceNamespace, &f.ResourceName,
		&f.Message, &f.Remediation, &f.VerificationSteps, &properties,
		&f.FirstSeen, &f.LastSeen, &f.LastScanID,
	)
	if err != nil {
		return storage.Finding{}, err
	}
	if len(properties) > 0 {
		if err := json.Unmarshal(properties, &f.Properties); err != nil {
			return storage.Finding{}, fmt.Errorf("decoding properties: %w", err)
		}
	}
	return f, nil
}

func (s *Store) GetFinding(ctx context.Context, clusterID uuid.UUID, source, fingerprint string) (storage.Finding, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+findingColumns+`
		FROM findings WHERE cluster_id = $1 AND source = $2 AND fingerprint = $3
	`, clusterID, source, fingerprint)
	f, err := scanFinding(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.Finding{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.Finding{}, fmt.Errorf("looking up finding: %w", err)
	}
	return f, nil
}

func (s *Store) ListFindings(ctx context.Context, clusterID uuid.UUID, filter storage.FindingFilter) ([]storage.Finding, error) {
	query := `SELECT ` + findingColumns + ` FROM findings WHERE cluster_id = $1`
	args := []any{clusterID}

	if filter.Source != "" {
		args = append(args, filter.Source)
		query += fmt.Sprintf(" AND source = $%d", len(args))
	}
	if filter.Severity != "" {
		args = append(args, filter.Severity)
		query += fmt.Sprintf(" AND severity = $%d", len(args))
	}
	if !filter.Since.IsZero() {
		args = append(args, filter.Since)
		query += fmt.Sprintf(" AND last_seen >= $%d", len(args))
	}
	query += " ORDER BY last_seen DESC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing findings: %w", err)
	}
	defer rows.Close()

	var out []storage.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning finding row: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListByResource is the cross-source/cross-cluster correlation query —
// see storage.FindingRepo.ListByResource's doc comment. clusterID ==
// uuid.Nil matches every cluster.
func (s *Store) ListByResource(ctx context.Context, clusterID uuid.UUID, kind, namespace, name string) ([]storage.Finding, error) {
	query := `SELECT ` + findingColumns + ` FROM findings WHERE resource_kind = $1 AND resource_namespace = $2 AND resource_name = $3`
	args := []any{kind, namespace, name}
	if clusterID != uuid.Nil {
		args = append(args, clusterID)
		query += fmt.Sprintf(" AND cluster_id = $%d", len(args))
	}
	query += " ORDER BY cluster_id, source"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing findings by resource: %w", err)
	}
	defer rows.Close()

	var out []storage.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning finding row: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) ListScans(ctx context.Context, clusterID uuid.UUID) ([]storage.Scan, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, cluster_id, source, generated_at, cluster_version, ingested_at
		FROM scans WHERE cluster_id = $1 ORDER BY generated_at DESC
	`, clusterID)
	if err != nil {
		return nil, fmt.Errorf("listing scans: %w", err)
	}
	defer rows.Close()

	var out []storage.Scan
	for rows.Next() {
		var sc storage.Scan
		if err := rows.Scan(&sc.ID, &sc.ClusterID, &sc.Source, &sc.GeneratedAt, &sc.ClusterVersion, &sc.IngestedAt); err != nil {
			return nil, fmt.Errorf("scanning scan row: %w", err)
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}
