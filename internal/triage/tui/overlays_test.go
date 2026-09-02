package tui

import (
	"strings"
	"testing"

	"github.com/rivo/tview"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

// TestConfirmBulkAction_SingleTargetProceedsWithoutDialog locks in that
// confirmBulkAction only gates genuinely bulk actions (>1 target) behind a
// dialog — 0 or 1 targets must call proceed directly, since a.pages is nil
// on a bare app (no running tview.Application) and touching it would panic;
// the >1 path needs a live Application and isn't covered here.
func TestConfirmBulkAction_SingleTargetProceedsWithoutDialog(t *testing.T) {
	a := &app{}
	sel := dedupRow("1", "policy.a", "msg", "ns", "app")

	called := false
	a.confirmBulkAction("prompt", nil, func() { called = true })
	if !called {
		t.Error("expected proceed to run immediately for 0 targets")
	}

	called = false
	a.confirmBulkAction("prompt", []triage.Row{sel}, func() { called = true })
	if !called {
		t.Error("expected proceed to run immediately for exactly 1 target")
	}
}

// TestRedraw_MirrorsStatusLineOntoActiveFlash is the fix for a real report:
// createJiraIssues' network call completes asynchronously (via
// QueueUpdateDraw), well after the keypress that started it — its
// completion handler only ever called a.redraw(), which used to touch
// nothing but "main"'s header/table/footer. A triager who opened the
// detail view, pressed 'j', and never left that page saw "Creating N Jira
// issue(s)..." frozen forever: the real result (success or a specific
// error) landed in a.statusLine and got redrawn into the invisible footer,
// with no way to know anything had even finished. redraw() must mirror
// a.statusLine onto whichever full-screen page's own status bar is
// currently active (a.activeFlash), not just the footer.
func TestRedraw_MirrorsStatusLineOntoActiveFlash(t *testing.T) {
	a := &app{
		header: tview.NewTextView(),
		table:  tview.NewTable(),
		footer: tview.NewTextView(),
	}

	var flashed string
	a.activeFlash = func(msg string) { flashed = msg }

	a.statusLine = "Created 0 Jira issue(s), 1 failed. Jira returned 401 Unauthorized"
	a.redraw()

	if flashed != a.statusLine {
		t.Errorf("expected redraw() to mirror statusLine onto activeFlash, got %q, want %q", flashed, a.statusLine)
	}
}

// TestRedraw_NilActiveFlashDoesNotPanic guards the common case ("main" is
// showing, no full-screen page active) — redraw() must not assume
// activeFlash is ever set.
func TestRedraw_NilActiveFlashDoesNotPanic(t *testing.T) {
	a := &app{
		header: tview.NewTextView(),
		table:  tview.NewTable(),
		footer: tview.NewTextView(),
	}
	a.statusLine = "some status"
	a.redraw() // must not panic with activeFlash == nil
}

// TestReanchorSelection_FollowsFindingAcrossResort is the fix for a real
// report: confirming a finding (via 'c', which triggers a.refresh()'s
// unconditional re-sort) and then immediately checking its status showed
// "not confirmed" — even though it plainly was. Root cause: tview.Table's
// selectedRow is a naked integer that Clear() does not reset; once
// refresh() resorts a.rows, the same row index can end up pointing at a
// completely different finding. reanchorSelection must follow the same
// FindingID to its new index instead of leaving the stale one.
func TestReanchorSelection_FollowsFindingAcrossResort(t *testing.T) {
	a := &app{table: tview.NewTable(), sortField: sortSeverity, sortAsc: false}
	// Initial order: "confirmed-me" (low) is at row 2 (index 1).
	a.rows = []triage.Row{
		rowWith("high-sev", findings.SeverityHigh, "ns", "a"),
		rowWith("confirmed-me", findings.SeverityLow, "ns", "b"),
	}
	a.table.Select(2, 0) // the user is looking at "confirmed-me"
	a.selectedID = "confirmed-me"

	// Simulate what confirming does: the finding's severity is unchanged,
	// but a totally different, higher-severity finding now sorts first —
	// same effect as any refresh() that reorders the list for any reason.
	a.rows = []triage.Row{
		rowWith("new-critical", findings.SeverityCritical, "ns", "c"),
		rowWith("high-sev", findings.SeverityHigh, "ns", "a"),
		rowWith("confirmed-me", findings.SeverityLow, "ns", "b"),
	}
	a.reanchorSelection()

	row, _ := a.table.GetSelection()
	if row != 3 {
		t.Fatalf("expected the cursor to follow \"confirmed-me\" to its new row 3, got row %d", row)
	}
	got, ok := a.selectedRow()
	if !ok || got.Entry.FindingID != "confirmed-me" {
		t.Errorf("expected selectedRow() to return \"confirmed-me\" after reanchoring, got %+v (ok=%v)", got, ok)
	}
}

// TestReanchorSelection_ClampsWhenFindingDisappeared covers the finding
// getting filtered/resolved away entirely — must not leave a stale index
// that could now belong to an unrelated finding.
func TestReanchorSelection_ClampsWhenFindingDisappeared(t *testing.T) {
	a := &app{table: tview.NewTable()}
	a.rows = []triage.Row{rowWith("a", findings.SeverityHigh, "ns", "a"), rowWith("b", findings.SeverityLow, "ns", "b")}
	a.table.Select(2, 0)
	a.selectedID = "b"

	a.rows = []triage.Row{rowWith("a", findings.SeverityHigh, "ns", "a")} // "b" is gone
	a.reanchorSelection()

	row, _ := a.table.GetSelection()
	if row != 1 {
		t.Errorf("expected the cursor clamped to the last valid row (1), got %d", row)
	}
}

// TestRedrawTable_JiraColumnShowsKeyOrDash is the visual half of the
// "how do I even know a ticket was filed" request — the JIRA column must
// show the filed ticket's key, and a plain "-" (not blank) when none.
func TestRedrawTable_JiraColumnShowsKeyOrDash(t *testing.T) {
	a := &app{header: tview.NewTextView(), table: tview.NewTable(), footer: tview.NewTextView()}
	filed := rowWith("1", findings.SeverityHigh, "ns", "a")
	filed.Entry.JiraIssueKey = "SEC-42"
	unfiled := rowWith("2", findings.SeverityLow, "ns", "b")
	a.rows = []triage.Row{filed, unfiled}

	a.redrawTable()

	got := strings.TrimSpace(a.table.GetCell(1, colJira).Text)
	if got != "SEC-42" {
		t.Errorf("expected the JIRA column to show the filed key, got %q", got)
	}
	got = strings.TrimSpace(a.table.GetCell(2, colJira).Text)
	if got != "-" {
		t.Errorf("expected the JIRA column to show \"-\" when unfiled, got %q", got)
	}
}

// TestStripDetailColorTags_RemovesOnlyKnownTagsNotUserBrackets guards the
// clipboard-copy path against eating literal bracketed text that happens
// to appear in a finding's own Message/Note (e.g. an IPv6 address) — it
// must only strip the exact literal tags detailText itself emits, not any
// "[...]"-shaped text.
func TestStripDetailColorTags_RemovesOnlyKnownTagsNotUserBrackets(t *testing.T) {
	in := "[yellow]Resource:[white] Pod default/app reaches [::1] via [red]note[white] [not-a-real-tag]"
	got := stripDetailColorTags(in)
	want := "Resource: Pod default/app reaches [::1] via note [not-a-real-tag]"
	if got != want {
		t.Errorf("stripDetailColorTags(%q) = %q, want %q", in, got, want)
	}
}

// TestDetailText_NoVerificationStepsSection guards against verification
// steps creeping back into the detail view — dropped deliberately (see
// docs/triage.md), the view now shows only what a filed ticket would
// contain (Title/Description/Remediation).
func TestDetailText_NoVerificationStepsSection(t *testing.T) {
	r := dedupRow("1", "policy.a", "the message", "ns", "app")
	r.Finding.VerificationSteps = "1. Do this. 2. Do that."
	a := &app{}

	out := a.detailText(r)
	if strings.Contains(out, "Verification") || strings.Contains(out, "Do this") {
		t.Errorf("expected no verification-steps content in the detail view, got:\n%s", out)
	}
}

// TestDetailText_NoKnowledgeBaseLabelSuffix guards the "clean output, no
// '(org knowledge base)' noise" fix: a knowledge-base override should
// blend in under the same plain labels as the default content, not be
// flagged inline every time it applies.
func TestDetailText_NoKnowledgeBaseLabelSuffix(t *testing.T) {
	r := dedupRow("1", "policy.a", "the message", "ns", "app")
	r.Finding.Remediation = "default remediation"
	a := &app{knowledgeBase: map[string]findings.KnowledgeBaseEntry{
		"policy.a": {Title: "Наш заголовок", Remediation: "Наша рекомендация"},
	}}

	out := a.detailText(r)
	if strings.Contains(out, "org knowledge base") || strings.Contains(out, "(org") {
		t.Errorf("expected clean labels with no parenthetical source annotation, got:\n%s", out)
	}
	if !strings.Contains(out, "Наш заголовок") || !strings.Contains(out, "Наша рекомендация") {
		t.Errorf("expected the knowledge-base override content to still render, got:\n%s", out)
	}
}
