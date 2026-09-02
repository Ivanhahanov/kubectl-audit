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
