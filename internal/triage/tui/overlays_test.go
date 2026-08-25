package tui

import (
	"testing"

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
