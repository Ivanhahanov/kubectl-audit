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

func scanAutomationRule(row pgx.Row) (storage.AutomationRule, error) {
	var r storage.AutomationRule
	var triggerRaw, actionRaw []byte
	err := row.Scan(&r.ID, &r.Name, &r.Enabled, &triggerRaw, &actionRaw, &r.CreatedAt)
	if err != nil {
		return storage.AutomationRule{}, err
	}
	if err := json.Unmarshal(triggerRaw, &r.Trigger); err != nil {
		return storage.AutomationRule{}, fmt.Errorf("decoding trigger: %w", err)
	}
	if err := json.Unmarshal(actionRaw, &r.Action); err != nil {
		return storage.AutomationRule{}, fmt.Errorf("decoding action: %w", err)
	}
	return r, nil
}

func (s *Store) CreateAutomationRule(ctx context.Context, rule storage.AutomationRule) (storage.AutomationRule, error) {
	trigger, err := json.Marshal(rule.Trigger)
	if err != nil {
		return storage.AutomationRule{}, fmt.Errorf("encoding trigger: %w", err)
	}
	action, err := json.Marshal(rule.Action)
	if err != nil {
		return storage.AutomationRule{}, fmt.Errorf("encoding action: %w", err)
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO automation_rules (name, enabled, trigger, action)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, enabled, trigger, action, created_at
	`, rule.Name, rule.Enabled, trigger, action)
	out, err := scanAutomationRule(row)
	if err != nil {
		return storage.AutomationRule{}, fmt.Errorf("creating automation rule: %w", err)
	}
	return out, nil
}

func (s *Store) GetAutomationRule(ctx context.Context, id uuid.UUID) (storage.AutomationRule, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, enabled, trigger, action, created_at FROM automation_rules WHERE id = $1
	`, id)
	out, err := scanAutomationRule(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.AutomationRule{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.AutomationRule{}, fmt.Errorf("looking up automation rule: %w", err)
	}
	return out, nil
}

func (s *Store) ListAutomationRules(ctx context.Context) ([]storage.AutomationRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, enabled, trigger, action, created_at FROM automation_rules ORDER BY created_at
	`)
	if err != nil {
		return nil, fmt.Errorf("listing automation rules: %w", err)
	}
	defer rows.Close()

	var out []storage.AutomationRule
	for rows.Next() {
		r, err := scanAutomationRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning automation rule row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) UpdateAutomationRule(ctx context.Context, rule storage.AutomationRule) error {
	trigger, err := json.Marshal(rule.Trigger)
	if err != nil {
		return fmt.Errorf("encoding trigger: %w", err)
	}
	action, err := json.Marshal(rule.Action)
	if err != nil {
		return fmt.Errorf("encoding action: %w", err)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE automation_rules SET name = $2, enabled = $3, trigger = $4, action = $5 WHERE id = $1
	`, rule.ID, rule.Name, rule.Enabled, trigger, action)
	if err != nil {
		return fmt.Errorf("updating automation rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteAutomationRule(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM automation_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting automation rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}
