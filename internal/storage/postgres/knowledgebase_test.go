package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

func TestKnowledgeBaseRepo_GetMissing(t *testing.T) {
	_, err := testStore.GetKnowledgeBaseEntry(context.Background(), "no-such-policy")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("err = %v, want storage.ErrNotFound", err)
	}
}

func TestKnowledgeBaseRepo_PutAndGet(t *testing.T) {
	ctx := context.Background()
	entry := storage.KnowledgeBaseEntry{
		PolicyID:    "workload.no-latest-tag-" + t.Name(),
		Title:       "Uses the latest tag",
		Category:    "workload-security",
		Description: "Pinning to :latest makes deployments non-reproducible.",
		Remediation: "Pin to a specific digest or version tag.",
		Labels:      []string{"supply-chain"},
	}
	if err := testStore.PutKnowledgeBaseEntry(ctx, entry); err != nil {
		t.Fatalf("PutKnowledgeBaseEntry: %v", err)
	}

	got, err := testStore.GetKnowledgeBaseEntry(ctx, entry.PolicyID)
	if err != nil {
		t.Fatalf("GetKnowledgeBaseEntry: %v", err)
	}
	if got.Title != entry.Title || got.Description != entry.Description || got.Remediation != entry.Remediation {
		t.Errorf("got %+v, want fields matching %+v", got, entry)
	}
	if len(got.Labels) != 1 || got.Labels[0] != "supply-chain" {
		t.Errorf("Labels = %v, want [supply-chain]", got.Labels)
	}
	if got.UpdatedAt.IsZero() {
		t.Error("expected a non-zero UpdatedAt")
	}
}

func TestKnowledgeBaseRepo_PutOverwritesExisting(t *testing.T) {
	ctx := context.Background()
	policyID := "workload.example-" + t.Name()
	if err := testStore.PutKnowledgeBaseEntry(ctx, storage.KnowledgeBaseEntry{PolicyID: policyID, Title: "v1"}); err != nil {
		t.Fatalf("PutKnowledgeBaseEntry (v1): %v", err)
	}
	if err := testStore.PutKnowledgeBaseEntry(ctx, storage.KnowledgeBaseEntry{PolicyID: policyID, Title: "v2"}); err != nil {
		t.Fatalf("PutKnowledgeBaseEntry (v2): %v", err)
	}

	got, err := testStore.GetKnowledgeBaseEntry(ctx, policyID)
	if err != nil {
		t.Fatalf("GetKnowledgeBaseEntry: %v", err)
	}
	if got.Title != "v2" {
		t.Errorf("Title = %q, want v2 (overwrite must replace, not merge)", got.Title)
	}
}
