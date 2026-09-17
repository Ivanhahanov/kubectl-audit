package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

func (s *Store) CreateExclusionRule(ctx context.Context, rule storage.ExclusionRule) (storage.ExclusionRule, error) {
	policyIDs := rule.PolicyIDs
	if policyIDs == nil {
		policyIDs = []string{}
	}
	match, err := json.Marshal(rule.Match)
	if err != nil {
		return storage.ExclusionRule{}, fmt.Errorf("encoding exclusion match: %w", err)
	}

	var out storage.ExclusionRule
	var matchRaw []byte
	err = s.pool.QueryRow(ctx, `
		INSERT INTO exclusion_rules (cluster_id, policy_ids, match, reason)
		VALUES ($1, $2, $3, $4)
		RETURNING id, cluster_id, policy_ids, match, reason, created_at
	`, rule.ClusterID, policyIDs, match, rule.Reason).Scan(
		&out.ID, &out.ClusterID, &out.PolicyIDs, &matchRaw, &out.Reason, &out.CreatedAt,
	)
	if err != nil {
		return storage.ExclusionRule{}, fmt.Errorf("creating exclusion rule: %w", err)
	}
	if err := json.Unmarshal(matchRaw, &out.Match); err != nil {
		return storage.ExclusionRule{}, fmt.Errorf("decoding exclusion match: %w", err)
	}
	return out, nil
}

func (s *Store) ListExclusionRules(ctx context.Context, clusterID *uuid.UUID) ([]storage.ExclusionRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, cluster_id, policy_ids, match, reason, created_at
		FROM exclusion_rules WHERE cluster_id IS NULL OR cluster_id = $1
		ORDER BY created_at
	`, clusterID)
	if err != nil {
		return nil, fmt.Errorf("listing exclusion rules: %w", err)
	}
	defer rows.Close()

	var out []storage.ExclusionRule
	for rows.Next() {
		var r storage.ExclusionRule
		var matchRaw []byte
		if err := rows.Scan(&r.ID, &r.ClusterID, &r.PolicyIDs, &matchRaw, &r.Reason, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning exclusion rule row: %w", err)
		}
		if err := json.Unmarshal(matchRaw, &r.Match); err != nil {
			return nil, fmt.Errorf("decoding exclusion match: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteExclusionRule(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM exclusion_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting exclusion rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}
