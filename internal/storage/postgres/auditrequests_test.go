package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

func TestAuditRequestRepo_CreateGetListUpdate(t *testing.T) {
	ctx := context.Background()
	cluster := newTestCluster(t)

	req, err := testStore.CreateAuditRequest(ctx, storage.AuditRequest{
		ClusterID:   cluster.ID,
		RequestedBy: "alice",
		Reason:      "quarterly compliance check",
	})
	if err != nil {
		t.Fatalf("CreateAuditRequest: %v", err)
	}
	if req.Status != storage.AuditRequestPending {
		t.Errorf("Status = %q, want pending as the default", req.Status)
	}

	got, err := testStore.GetAuditRequest(ctx, req.ID)
	if err != nil {
		t.Fatalf("GetAuditRequest: %v", err)
	}
	if got.RequestedBy != "alice" || got.Reason != "quarterly compliance check" {
		t.Errorf("got %+v", got)
	}

	otherCluster := newTestCluster(t)
	list, err := testStore.ListAuditRequests(ctx, &otherCluster.ID)
	if err != nil {
		t.Fatalf("ListAuditRequests (other cluster): %v", err)
	}
	for _, r := range list {
		if r.ID == req.ID {
			t.Error("a request for one cluster must not appear when listing another cluster's requests")
		}
	}

	listOwner, err := testStore.ListAuditRequests(ctx, &cluster.ID)
	if err != nil {
		t.Fatalf("ListAuditRequests (owner): %v", err)
	}
	found := false
	for _, r := range listOwner {
		if r.ID == req.ID {
			found = true
		}
	}
	if !found {
		t.Error("expected the request to appear when listing its own cluster")
	}

	got.Status = storage.AuditRequestApproved
	got.TektonPipelineRunName = "scan-run-abc123"
	if err := testStore.UpdateAuditRequest(ctx, got); err != nil {
		t.Fatalf("UpdateAuditRequest: %v", err)
	}
	updated, err := testStore.GetAuditRequest(ctx, req.ID)
	if err != nil {
		t.Fatalf("GetAuditRequest (after update): %v", err)
	}
	if updated.Status != storage.AuditRequestApproved {
		t.Errorf("Status = %q, want approved", updated.Status)
	}
	if updated.TektonPipelineRunName != "scan-run-abc123" {
		t.Errorf("TektonPipelineRunName = %q", updated.TektonPipelineRunName)
	}
}

func TestAuditRequestRepo_ScheduledCron(t *testing.T) {
	ctx := context.Background()
	cluster := newTestCluster(t)
	cron := "0 3 * * *"

	req, err := testStore.CreateAuditRequest(ctx, storage.AuditRequest{
		ClusterID:     cluster.ID,
		Reason:        "nightly scan",
		ScheduledCron: &cron,
	})
	if err != nil {
		t.Fatalf("CreateAuditRequest: %v", err)
	}
	got, err := testStore.GetAuditRequest(ctx, req.ID)
	if err != nil {
		t.Fatalf("GetAuditRequest: %v", err)
	}
	if got.ScheduledCron == nil || *got.ScheduledCron != cron {
		t.Errorf("ScheduledCron = %v, want %q", got.ScheduledCron, cron)
	}
}

func TestAuditRequestRepo_GetMissing(t *testing.T) {
	if _, err := testStore.GetAuditRequest(context.Background(), uuid.New()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("err = %v, want storage.ErrNotFound", err)
	}
}
