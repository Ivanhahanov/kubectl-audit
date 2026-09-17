package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

func TestAutomationRuleRepo_CreateGetListUpdateDelete(t *testing.T) {
	ctx := context.Background()
	rule, err := testStore.CreateAutomationRule(ctx, storage.AutomationRule{
		Name:    "file critical confirmed findings",
		Enabled: true,
		Trigger: storage.AutomationTrigger{MinSeverity: "CRITICAL", Status: "confirmed", NoJiraLinkForHours: 24},
		Action:  storage.AutomationAction{Type: "file_jira"},
	})
	if err != nil {
		t.Fatalf("CreateAutomationRule: %v", err)
	}
	if rule.ID.String() == "" {
		t.Fatal("expected a generated ID")
	}

	got, err := testStore.GetAutomationRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("GetAutomationRule: %v", err)
	}
	if got.Trigger.MinSeverity != "CRITICAL" || got.Trigger.NoJiraLinkForHours != 24 {
		t.Errorf("Trigger round-tripped incorrectly: %+v", got.Trigger)
	}
	if got.Action.Type != "file_jira" {
		t.Errorf("Action.Type = %q, want file_jira", got.Action.Type)
	}

	list, err := testStore.ListAutomationRules(ctx)
	if err != nil {
		t.Fatalf("ListAutomationRules: %v", err)
	}
	found := false
	for _, r := range list {
		if r.ID == rule.ID {
			found = true
		}
	}
	if !found {
		t.Error("expected the created rule to appear in ListAutomationRules")
	}

	got.Enabled = false
	got.Action = storage.AutomationAction{Type: "agent_triage", Prompt: "investigate", Tools: []string{"inspect_resource"}}
	if err := testStore.UpdateAutomationRule(ctx, got); err != nil {
		t.Fatalf("UpdateAutomationRule: %v", err)
	}
	updated, err := testStore.GetAutomationRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("GetAutomationRule (after update): %v", err)
	}
	if updated.Enabled {
		t.Error("expected Enabled = false after update")
	}
	if updated.Action.Type != "agent_triage" || len(updated.Action.Tools) != 1 {
		t.Errorf("Action after update = %+v", updated.Action)
	}

	if err := testStore.DeleteAutomationRule(ctx, rule.ID); err != nil {
		t.Fatalf("DeleteAutomationRule: %v", err)
	}
	if _, err := testStore.GetAutomationRule(ctx, rule.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("err after delete = %v, want storage.ErrNotFound", err)
	}
}

func TestAutomationRuleRepo_GetMissing(t *testing.T) {
	_, err := testStore.GetAutomationRule(context.Background(), uuid.New())
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("err = %v, want storage.ErrNotFound", err)
	}
}
