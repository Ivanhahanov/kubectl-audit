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
