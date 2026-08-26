package tui

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

func rowWith(id string, sev findings.Severity, ns, name string) triage.Row {
	f := findings.Finding{
		ID: id, PolicyID: "workload.no-latest-tag", Title: "t", Severity: sev,
		Category: "supply-chain", Resource: findings.ResourceRef{Kind: "Deployment", Namespace: ns, Name: name},
		Message: "m",
	}
	return triage.Row{
		Finding:  &f,
		Entry:    triage.Entry{FindingID: id, PolicyID: f.PolicyID, Resource: f.Resource, Title: f.Title},
		GroupKey: triage.GroupKey(f.Resource),
	}
}

func TestSortRows_BySeverityDescendingByDefault(t *testing.T) {
	rows := []triage.Row{
		rowWith("1", findings.SeverityLow, "ns", "a"),
		rowWith("2", findings.SeverityCritical, "ns", "b"),
		rowWith("3", findings.SeverityMedium, "ns", "c"),
	}
	sortRows(rows, sortSeverity, false, nil)
	if rows[0].Entry.FindingID != "2" || rows[1].Entry.FindingID != "3" || rows[2].Entry.FindingID != "1" {
		t.Errorf("expected critical, medium, low order, got %v, %v, %v",
			rows[0].Entry.FindingID, rows[1].Entry.FindingID, rows[2].Entry.FindingID)
	}
}

func TestSortRows_AscendingReversesOrder(t *testing.T) {
	rows := []triage.Row{
		rowWith("1", findings.SeverityLow, "ns", "a"),
		rowWith("2", findings.SeverityCritical, "ns", "b"),
	}
	sortRows(rows, sortSeverity, true, nil)
	if rows[0].Entry.FindingID != "1" || rows[1].Entry.FindingID != "2" {
		t.Errorf("expected low then critical (ascending), got %v, %v", rows[0].Entry.FindingID, rows[1].Entry.FindingID)
	}
}

func TestSortRows_ResolvedRowsAlwaysLast(t *testing.T) {
	resolved := rowWith("resolved", findings.SeverityCritical, "ns", "z")
	resolved.Finding = nil
	resolved.Entry.Status = triage.StatusResolved
	rows := []triage.Row{resolved, rowWith("active", findings.SeverityLow, "ns", "a")}

	sortRows(rows, sortSeverity, false, nil)
	if rows[len(rows)-1].Entry.FindingID != "resolved" {
		t.Errorf("expected the resolved row to sort last regardless of severity, got order %v", rows)
	}
}

func TestSortRows_ByKindNamespaceAlphabetical(t *testing.T) {
	rows := []triage.Row{
		rowWith("1", findings.SeverityLow, "zeta", "a"),
		rowWith("2", findings.SeverityLow, "alpha", "b"),
	}
	sortRows(rows, sortNS, true, nil)
	if rows[0].Entry.FindingID != "2" {
		t.Errorf("expected alpha before zeta ascending, got %v first", rows[0].Entry.FindingID)
	}
}

func TestSortRows_ByCountUsesFindingIDKeyedMap(t *testing.T) {
	rows := []triage.Row{
		rowWith("small", findings.SeverityLow, "ns", "a"),
		rowWith("big", findings.SeverityLow, "ns", "b"),
	}
	counts := map[string]int{"small": 2, "big": 12}
	sortRows(rows, sortCount, true, counts)
	if rows[0].Entry.FindingID != "small" || rows[1].Entry.FindingID != "big" {
		t.Errorf("expected ascending count order (small, big), got %v, %v", rows[0].Entry.FindingID, rows[1].Entry.FindingID)
	}
}

func TestFilterRows_MatchesAcrossFields(t *testing.T) {
	rows := []triage.Row{
		rowWith("1", findings.SeverityLow, "default", "web-app"),
		rowWith("2", findings.SeverityLow, "default", "worker"),
	}
	out := filterRows(rows, "web-app")
	if len(out) != 1 || out[0].Entry.FindingID != "1" {
		t.Errorf("expected only the web-app row to match, got %v", out)
	}
}

func TestFilterRows_EmptyQueryReturnsAll(t *testing.T) {
	rows := []triage.Row{rowWith("1", findings.SeverityLow, "default", "a")}
	if out := filterRows(rows, ""); len(out) != 1 {
		t.Errorf("expected an empty filter to return everything, got %d rows", len(out))
	}
}

func TestSortFieldForDigit(t *testing.T) {
	cases := map[rune]sortField{'1': sortSeverity, '2': sortStatus, '7': sortTags}
	for digit, want := range cases {
		got, ok := sortFieldForDigit(digit)
		if !ok || got != want {
			t.Errorf("sortFieldForDigit(%q) = %v, %v; want %v, true", digit, got, ok, want)
		}
	}
	if _, ok := sortFieldForDigit('8'); ok {
		t.Error("expected digit '8' (out of range — only 7 sortable columns) to not map to a sort field")
	}
	if _, ok := sortFieldForDigit('a'); ok {
		t.Error("expected a non-digit rune to not map to a sort field")
	}
}

func TestPolicyStats_TalliesByPolicyAndSortsByCountDesc(t *testing.T) {
	rows := []triage.Row{
		dedupRow("1", "policy.small", "m", "ns", "a"),
		dedupRow("2", "policy.big", "m", "ns", "a"),
		dedupRow("3", "policy.big", "m", "ns", "b"),
		dedupRow("4", "policy.big", "m", "ns", "c"),
	}
	stats := policyStats(rows)
	if len(stats) != 2 {
		t.Fatalf("expected 2 distinct policies, got %d", len(stats))
	}
	if stats[0].PolicyID != "policy.big" || stats[0].Count != 3 {
		t.Errorf("expected policy.big (count 3) first, got %+v", stats[0])
	}
	if stats[1].PolicyID != "policy.small" || stats[1].Count != 1 {
		t.Errorf("expected policy.small (count 1) second, got %+v", stats[1])
	}
}

func TestPolicyStats_CountsNewAndConfirmed(t *testing.T) {
	confirmed := dedupRow("1", "policy.a", "m", "ns", "a")
	confirmed.Entry.Status = triage.StatusConfirmed
	rows := []triage.Row{
		confirmed,
		dedupRow("2", "policy.a", "m", "ns", "b"), // default Status "" reads as New
	}
	stats := policyStats(rows)
	if len(stats) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(stats))
	}
	if stats[0].Count != 2 || stats[0].New != 1 || stats[0].Confirmed != 1 {
		t.Errorf("expected Count=2 New=1 Confirmed=1, got %+v", stats[0])
	}
}

func TestPolicyStats_DefaultSortIsCountDescending(t *testing.T) {
	rows := []triage.Row{
		dedupRow("1", "policy.small", "m", "ns", "a"),
		dedupRow("2", "policy.big", "m", "ns", "a"),
		dedupRow("3", "policy.big", "m", "ns", "b"),
	}
	stats := policyStats(rows)
	if stats[0].PolicyID != "policy.big" {
		t.Errorf("expected policy.big (count 2) first by default, got %+v", stats[0])
	}
}

func TestSortPolicyStats_ByPolicyIDAscending(t *testing.T) {
	stats := []policyStat{
		{PolicyID: "zeta", Count: 1},
		{PolicyID: "alpha", Count: 1},
	}
	sortPolicyStats(stats, policySortPolicyID, true)
	if stats[0].PolicyID != "alpha" || stats[1].PolicyID != "zeta" {
		t.Errorf("expected alpha before zeta ascending, got %v", stats)
	}
}

func TestSortPolicyStats_ByNewDescendingByDefault(t *testing.T) {
	stats := []policyStat{
		{PolicyID: "a", New: 1},
		{PolicyID: "b", New: 5},
	}
	sortPolicyStats(stats, policySortNew, false)
	if stats[0].PolicyID != "b" {
		t.Errorf("expected the higher New count first (descending), got %+v", stats)
	}
}

func TestPolicyStatSortFieldForDigit(t *testing.T) {
	cases := map[rune]policyStatSortField{'1': policySortSeverity, '3': policySortCount, '6': policySortTitle}
	for digit, want := range cases {
		got, ok := policyStatSortFieldForDigit(digit)
		if !ok || got != want {
			t.Errorf("policyStatSortFieldForDigit(%q) = %v, %v; want %v, true", digit, got, ok, want)
		}
	}
	if _, ok := policyStatSortFieldForDigit('7'); ok {
		t.Error("expected digit '7' (out of range — only 6 sortable columns) to not map to a sort field")
	}
}

func TestEffectiveColumnWidths_UnknownTermWidthReturnsStatic(t *testing.T) {
	if w := effectiveColumnWidths(0); w != columnWidths {
		t.Errorf("expected termWidth<=0 to return columnWidths unchanged, got %v", w)
	}
}

func TestEffectiveColumnWidths_NarrowTerminalLeavesMinimumUntouched(t *testing.T) {
	// Narrower than the static total — nothing to grow into.
	w := effectiveColumnWidths(50)
	if w[colNamespaceName] != columnWidths[colNamespaceName] {
		t.Errorf("expected the minimum width to stay unchanged on a narrow terminal, got %d", w[colNamespaceName])
	}
}

func TestEffectiveColumnWidths_WideTerminalGrowsNamespaceNameColumn(t *testing.T) {
	fixed := 0
	for i, cw := range columnWidths {
		if i != colNamespaceName {
			fixed += cw
		}
	}
	overhead := (columnCount - 1) + 2
	available := columnWidths[colNamespaceName] + 60 // however wide NAMESPACE/NAME ends up
	termWidth := fixed + overhead + available

	w := effectiveColumnWidths(termWidth)
	if w[colNamespaceName] != available {
		t.Errorf("expected NAMESPACE/NAME to grow to fill the leftover room (%d), got %d", available, w[colNamespaceName])
	}
	for i, cw := range w {
		if i != colNamespaceName && cw != columnWidths[i] {
			t.Errorf("expected column %d to stay at its static width, got %d want %d", i, cw, columnWidths[i])
		}
	}
}
