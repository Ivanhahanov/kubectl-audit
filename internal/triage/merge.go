package triage

import (
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/report"
)

// Row is one line of the triage view: either a live finding (Finding
// non-nil) or a StatusResolved row for an Entry whose finding is no longer
// produced by the latest scan (Finding nil — only the Entry's snapshot
// fields are known, since the original findings.Finding is gone).
// Suppressed marks a finding that an exclusion rule matched (see
// report.SuppressedFinding) — still triageable like any other finding, just
// worth distinguishing in a view, since it's already excluded from
// Summary/--fail-on/CSV upstream.
type Row struct {
	Finding        *findings.Finding
	Entry          Entry
	GroupKey       string
	Suppressed     bool
	SuppressReason string
}

// GroupKey is the same Kind+name-shape clustering internal/report uses to
// collapse repeated Markdown rows (see report.NameTemplate) — reused here
// so the TUI's "apply this decision to every matching finding" bulk action
// targets exactly the set of findings a triager would already expect to be
// near-duplicates from looking at the collapsed report.
func GroupKey(ref findings.ResourceRef) string {
	return ref.Kind + "|" + report.NameTemplate(ref.Name)
}

// Merge joins current (the latest scan's active findings) and suppressed
// (the same scan's exclusion-rule-matched findings, see
// report.SuppressedFinding) with state by Finding.ID and returns one Row
// per finding, active, suppressed, or resolved.
//
// A finding with no matching Entry gets a fresh, unpersisted Status:
// StatusNew Entry (nothing is written to state until a human acts on it —
// see State.SetStatus/SetNote). A state Entry whose FindingID is in
// NEITHER current NOR suppressed (and isn't already StatusResolved) is
// mutated in place to StatusResolved — the caller must SaveState after
// calling Merge for that transition to persist, but it's computed
// automatically here rather than requiring a human to notice and record it
// manually. Folding both sets together for this check means a finding that
// moves between active and suppressed across scans (e.g. an exclusion rule
// was added or removed) is never spuriously marked resolved just because
// it left one of the two lists.
func Merge(current []findings.Finding, suppressed []report.SuppressedFinding, state *State, now time.Time) []Row {
	seenIDs := make(map[string]bool, len(current)+len(suppressed))
	rows := make([]Row, 0, len(current)+len(suppressed))

	entryFor := func(f findings.Finding) Entry {
		e, ok := state.Entries[f.ID]
		if !ok {
			e = Entry{FindingID: f.ID, PolicyID: f.PolicyID, Resource: f.Resource, Title: f.Title, Status: StatusNew}
		}
		return e
	}

	for i := range current {
		f := current[i]
		seenIDs[f.ID] = true
		rows = append(rows, Row{Finding: &current[i], Entry: entryFor(f), GroupKey: GroupKey(f.Resource)})
	}

	for i := range suppressed {
		f := suppressed[i].Finding
		seenIDs[f.ID] = true
		rows = append(rows, Row{
			Finding: &suppressed[i].Finding, Entry: entryFor(f), GroupKey: GroupKey(f.Resource),
			Suppressed: true, SuppressReason: suppressed[i].Reason,
		})
	}

	for id, e := range state.Entries {
		if seenIDs[id] {
			continue
		}
		if e.Status != StatusResolved {
			e.Status = StatusResolved
			e.LastUpdated = now
			state.Entries[id] = e
		}
		rows = append(rows, Row{Finding: nil, Entry: e, GroupKey: GroupKey(e.Resource)})
	}

	return rows
}

// GroupCounts tallies how many rows share each GroupKey — the number a
// bulk-apply action would affect. Only counts rows that aren't already
// StatusResolved (a resolved finding is never a bulk-apply target).
func GroupCounts(rows []Row) map[string]int {
	counts := make(map[string]int)
	for _, r := range rows {
		if r.Entry.Status == StatusResolved {
			continue
		}
		counts[r.GroupKey]++
	}
	return counts
}
