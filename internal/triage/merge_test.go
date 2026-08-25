package triage_test

import (
	"testing"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/report"
	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

func TestMerge_NewFindingGetsStatusNew(t *testing.T) {
	state := &triage.State{Entries: map[string]triage.Entry{}}
	rows := triage.Merge([]findings.Finding{mustFinding("f1")}, nil, state, time.Now())
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].Entry.Status != triage.StatusNew {
		t.Errorf("expected StatusNew for an untriaged finding, got %q", rows[0].Entry.Status)
	}
	if rows[0].Finding == nil || rows[0].Finding.ID != "f1" {
		t.Errorf("expected the live Finding to be attached, got %+v", rows[0].Finding)
	}
	// A never-triaged finding must not be written into state by Merge
	// alone — only an explicit human action (SetStatus/SetNote/SetTags)
	// persists an entry.
	if _, ok := state.Entries["f1"]; ok {
		t.Error("expected Merge to not persist an entry for an untouched finding")
	}
}

func TestMerge_ExistingTriageDecisionPreserved(t *testing.T) {
	now := time.Now()
	state := &triage.State{Entries: map[string]triage.Entry{}}
	f := mustFinding("f1")
	if err := state.SetStatus(f, triage.StatusConfirmed, now); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	rows := triage.Merge([]findings.Finding{f}, nil, state, now)
	if len(rows) != 1 || rows[0].Entry.Status != triage.StatusConfirmed {
		t.Fatalf("expected the prior StatusConfirmed decision to survive a re-merge, got %+v", rows)
	}
}

// TestMerge_DisappearedFindingBecomesResolved is the core "the fix landed"
// signal: a finding that had a triage entry but is no longer produced by
// the latest scan must show up as StatusResolved, not silently vanish.
func TestMerge_DisappearedFindingBecomesResolved(t *testing.T) {
	now := time.Now()
	state := &triage.State{Entries: map[string]triage.Entry{}}
	gone := mustFinding("gone-id")
	if err := state.SetStatus(gone, triage.StatusConfirmed, now); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	// Latest scan no longer produces "gone-id" at all.
	rows := triage.Merge(nil, nil, state, now)
	if len(rows) != 1 {
		t.Fatalf("expected exactly one resolved row, got %+v", rows)
	}
	if rows[0].Finding != nil {
		t.Errorf("expected a resolved row to have no live Finding, got %+v", rows[0].Finding)
	}
	if rows[0].Entry.Status != triage.StatusResolved {
		t.Errorf("expected StatusResolved, got %q", rows[0].Entry.Status)
	}
	if rows[0].Entry.PolicyID != gone.PolicyID || rows[0].Entry.Resource.Name != gone.Resource.Name {
		t.Errorf("expected the resolved row to retain the original finding's snapshot, got %+v", rows[0].Entry)
	}
	// The transition must actually be persisted into state (Merge mutates
	// its state argument), not just reflected in the returned Row.
	if state.Entries["gone-id"].Status != triage.StatusResolved {
		t.Errorf("expected Merge to persist the StatusResolved transition into state, got %q", state.Entries["gone-id"].Status)
	}
}

func TestMerge_AlreadyResolvedStaysResolvedNotReRun(t *testing.T) {
	now := time.Now()
	state := &triage.State{Entries: map[string]triage.Entry{
		"old": {FindingID: "old", Status: triage.StatusResolved, LastUpdated: now.Add(-time.Hour)},
	}}
	rows := triage.Merge(nil, nil, state, now)
	if len(rows) != 1 {
		t.Fatalf("expected exactly one row, got %+v", rows)
	}
	if !rows[0].Entry.LastUpdated.Equal(now.Add(-time.Hour)) {
		t.Errorf("expected an already-resolved entry's LastUpdated to be left alone, got %v", rows[0].Entry.LastUpdated)
	}
}

func TestMerge_SuppressedFindingIsRowWithReason(t *testing.T) {
	state := &triage.State{Entries: map[string]triage.Entry{}}
	f := mustFinding("s1")
	rows := triage.Merge(nil, []report.SuppressedFinding{{Finding: f, Reason: "known cilium-agent exception"}}, state, time.Now())
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if !rows[0].Suppressed {
		t.Error("expected Suppressed to be true")
	}
	if rows[0].SuppressReason != "known cilium-agent exception" {
		t.Errorf("expected the exclusion rule's reason to be attached, got %q", rows[0].SuppressReason)
	}
	if rows[0].Finding == nil || rows[0].Finding.ID != "s1" {
		t.Errorf("expected the live Finding to be attached to a suppressed row too, got %+v", rows[0].Finding)
	}
}

// TestMerge_SuppressedThenActiveDoesNotBecomeResolved is the transition
// this dual-list design exists for: a finding that was suppressed on one
// scan and is active (no longer excluded) on the next must never be
// spuriously marked resolved just because it briefly left one of the two
// lists — it's continuously present across both.
func TestMerge_SuppressedThenActiveDoesNotBecomeResolved(t *testing.T) {
	now := time.Now()
	state := &triage.State{Entries: map[string]triage.Entry{}}
	f := mustFinding("flip")
	if err := state.SetStatus(f, triage.StatusConfirmed, now); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	// Previously suppressed; now scan reports it as active instead.
	rows := triage.Merge([]findings.Finding{f}, nil, state, now)
	if len(rows) != 1 || rows[0].Entry.Status == triage.StatusResolved {
		t.Fatalf("expected the finding to stay StatusConfirmed (not resolved) after moving from suppressed to active, got %+v", rows)
	}
	if rows[0].Suppressed {
		t.Error("expected the row to reflect its current (active) state, not suppressed")
	}
}

func TestGroupKey_MatchesReportNameTemplateShape(t *testing.T) {
	a := triage.GroupKey(findings.ResourceRef{Kind: "Namespace", Name: "usersvs-0004237b-3813-48ce-a48f-3cabdaeccbea"})
	b := triage.GroupKey(findings.ResourceRef{Kind: "Namespace", Name: "usersvs-0006e164-99bc-4fac-aaec-079df475fa6b"})
	if a != b {
		t.Errorf("expected two UUID-suffixed names of the same Kind to share a GroupKey, got %q vs %q", a, b)
	}
	c := triage.GroupKey(findings.ResourceRef{Kind: "Namespace", Name: "argocd"})
	if a == c {
		t.Errorf("expected a hand-chosen name to NOT share a GroupKey with the UUID-suffixed ones, got %q", c)
	}
}

func TestGroupCounts_ExcludesResolvedRows(t *testing.T) {
	rows := []triage.Row{
		{GroupKey: "g1", Entry: triage.Entry{Status: triage.StatusNew}},
		{GroupKey: "g1", Entry: triage.Entry{Status: triage.StatusConfirmed}},
		{GroupKey: "g1", Entry: triage.Entry{Status: triage.StatusResolved}},
	}
	counts := triage.GroupCounts(rows)
	if counts["g1"] != 2 {
		t.Errorf("expected resolved rows excluded from group counts, got %d", counts["g1"])
	}
}
