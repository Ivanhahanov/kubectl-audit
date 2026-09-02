package triage_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

func mustFinding(id string) findings.Finding {
	return findings.Finding{
		ID: id, PolicyID: "workload.no-latest-tag", Title: "t", Severity: findings.SeverityLow,
		Category: "supply-chain", Resource: findings.ResourceRef{Kind: "Deployment", Namespace: "default", Name: "app"},
		Message: "m",
	}
}

func TestLoadState_MissingFileIsEmptyNotError(t *testing.T) {
	s, err := triage.LoadState(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if s == nil || s.Entries == nil || len(s.Entries) != 0 {
		t.Errorf("expected an empty, non-nil State, got %+v", s)
	}
}

func TestSaveLoadState_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "triage-state.yaml")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	s, _ := triage.LoadState(path)
	f := mustFinding("abc123")
	if err := s.SetStatus(f, triage.StatusConfirmed, now); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	s.SetNote(f, "definitely exploitable", now)

	if err := triage.SaveState(path, s); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	reloaded, err := triage.LoadState(path)
	if err != nil {
		t.Fatalf("LoadState (reload): %v", err)
	}
	e, ok := reloaded.Entries["abc123"]
	if !ok {
		t.Fatalf("expected entry abc123 to round-trip, got %+v", reloaded.Entries)
	}
	if e.Status != triage.StatusConfirmed {
		t.Errorf("expected status confirmed, got %q", e.Status)
	}
	if e.Note != "definitely exploitable" {
		t.Errorf("expected note to round-trip, got %q", e.Note)
	}
	if e.PolicyID != "workload.no-latest-tag" || e.Resource.Name != "app" {
		t.Errorf("expected the finding snapshot (PolicyID/Resource) to be captured, got %+v", e)
	}
}

// TestSetStatus_RejectsNonHumanStatuses guards StatusNew/StatusResolved
// from being set directly by a human action — StatusNew is the implicit
// absence of an entry, and StatusResolved is Merge-computed only.
func TestSetStatus_RejectsNonHumanStatuses(t *testing.T) {
	s := &triage.State{Entries: map[string]triage.Entry{}}
	f := mustFinding("x")
	for _, bad := range []triage.Status{triage.StatusNew, triage.StatusResolved} {
		if err := s.SetStatus(f, bad, time.Now()); err == nil {
			t.Errorf("expected SetStatus(%q) to be rejected", bad)
		}
	}
}

func TestResetStatus_RevertsToNew(t *testing.T) {
	s := &triage.State{Entries: map[string]triage.Entry{}}
	f := mustFinding("z")
	if err := s.SetStatus(f, triage.StatusConfirmed, time.Now()); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	s.ResetStatus(f, time.Now())
	e, ok := s.Entries["z"]
	if !ok {
		t.Fatal("expected the entry to still exist after ResetStatus")
	}
	if e.Status != triage.StatusNew {
		t.Errorf("expected status to revert to new, got %q", e.Status)
	}
}

func TestResetStatus_NoOpOnNeverTriagedFinding(t *testing.T) {
	s := &triage.State{Entries: map[string]triage.Entry{}}
	f := mustFinding("never-triaged")
	s.ResetStatus(f, time.Now())
	e, ok := s.Entries["never-triaged"]
	if !ok {
		t.Fatal("expected ResetStatus to create an entry from the finding's snapshot")
	}
	if e.Status != triage.StatusNew {
		t.Errorf("expected status new, got %q", e.Status)
	}
}

func TestSetNote_CreatesEntryIfMissing(t *testing.T) {
	s := &triage.State{Entries: map[string]triage.Entry{}}
	f := mustFinding("y")
	s.SetNote(f, "worth a look", time.Now())
	e, ok := s.Entries["y"]
	if !ok {
		t.Fatal("expected SetNote to create an entry")
	}
	if e.Status != triage.StatusNew {
		t.Errorf("expected a freshly created entry's status to be StatusNew, got %q", e.Status)
	}
	if e.Note != "worth a look" {
		t.Errorf("expected the note to be set, got %q", e.Note)
	}
}
