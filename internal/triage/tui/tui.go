// Package tui is the interactive `kubectl audit triage` screen: a k9s-style
// table of findings joined with their triage state (see internal/triage),
// with hotkeys to mark a decision, add notes/tags, bulk-apply a decision to
// every finding that looks like the same repeated per-tenant/per-namespace
// pattern, and create Jira tickets directly. Every mutating action calls
// straight through to internal/triage's State methods and saves
// immediately — the TUI itself holds no triage state of its own beyond the
// current view (filter/sort/marks).
package tui

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/report"
	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

const (
	// Content lines + 2 for the top/bottom border each now draws.
	headerHeight = 4 + 2
	footerHeight = 3 + 2
)

// app holds everything the running TUI needs. all/suppressed are the
// immutable sets from the loaded findings.json; state is mutated in place
// by every triage action and saved to statePath after each one.
type app struct {
	tv     *tview.Application
	header *tview.TextView
	search *tview.InputField
	table  *tview.Table
	footer *tview.TextView
	pages  *tview.Pages

	all            []findings.Finding
	suppressed     []report.SuppressedFinding
	state          *triage.State
	statePath      string
	target         string
	findingsPath   string
	jira           JiraConfig
	dedupThreshold int

	merged       []triage.Row            // full merge, unfiltered — source of truth for header totals
	rows         []triage.Row            // merged, filtered/collapsed/focused, sorted, suppressed-hidden-unless-shown
	dedupMembers map[string][]triage.Row // representative row's FindingID -> its full dedup bucket (see dedupGroups)

	sortField sortField
	sortAsc   bool
	filter    string

	collapse     bool   // whether dedup collapsing (see dedupGroups) is applied at all — toggled by 'r'
	expandGroup  string // non-empty: drill into this one dedupKey's individual members — toggled by 'g'
	systemFilter string // non-empty: isolate to this namespace (or Name for cluster-scoped) across every policy/kind — toggled by 's'

	showSuppressed bool
	marked         map[string]bool // keyed by Entry.FindingID

	saveErr    error
	statusLine string // last-action feedback shown in the footer (Jira result, errors, ...)
}

// Config is everything Run needs beyond the findings/state themselves.
type Config struct {
	Target       string // report.Result.Target-style label, shown in the header
	FindingsPath string
	StatePath    string
	Jira         JiraConfig // may be zero-value; the 'j' action reports a clear error if so
	// DedupThreshold is the same "collapse a repeated finding once it hits
	// this many near-identical instances" knob as
	// config.OutputConfig.NamespaceGroupThreshold — one dial shared with
	// the Markdown report so both mean the same thing. <= 0 disables
	// collapsing.
	DedupThreshold int
}

// Run opens the interactive triage TUI and blocks until the user quits.
func Run(all []findings.Finding, suppressed []report.SuppressedFinding, state *triage.State, cfg Config) error {
	a := &app{
		tv:  tview.NewApplication(),
		all: all, suppressed: suppressed, state: state,
		statePath: cfg.StatePath, target: cfg.Target, findingsPath: cfg.FindingsPath,
		jira:           cfg.Jira,
		dedupThreshold: cfg.DedupThreshold,
		sortField:      sortSeverity, sortAsc: false,
		// Off by default: collapsing changes what you're looking at
		// without being asked, and a bulk action on a collapsed row
		// affects every finding it stands for — someone who hasn't
		// explicitly opted in via 'r' should never risk silently losing
		// sight of (or bulk-triaging) findings they didn't mean to.
		collapse: false,
		marked:   map[string]bool{},
	}
	a.refresh()

	a.header = tview.NewTextView().SetDynamicColors(true)
	a.header.SetBorder(true).SetBorderColor(theme.borderFg)

	a.footer = tview.NewTextView().SetDynamicColors(true)
	a.footer.SetBorder(true).SetBorderColor(theme.borderFg)

	a.search = tview.NewInputField().
		SetLabel(" 🔍 ").
		SetLabelColor(theme.accent).
		SetFieldBackgroundColor(tcell.ColorBlack).
		SetFieldTextColor(tcell.ColorWhite).
		SetPlaceholder("press / to search — live filter over title/policy/resource/message").
		SetPlaceholderTextColor(theme.dim)
	a.search.SetChangedFunc(func(text string) {
		a.filter = text
		a.refresh()
		a.redraw()
	})
	a.search.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape {
			a.search.SetText("")
			a.filter = ""
			a.refresh()
		}
		a.tv.SetFocus(a.table)
		a.redraw()
	})

	a.table = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	a.table.SetSelectedStyle(tcell.StyleDefault.Background(theme.selectionBg).Foreground(theme.selectionFg).Bold(true))
	a.table.SetInputCapture(a.handleKey)
	a.table.SetBorder(true).SetBorderColor(theme.borderFg).SetTitle(" findings ").SetTitleColor(theme.accent)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.header, headerHeight, 0, false).
		AddItem(a.search, 1, 0, false).
		AddItem(a.table, 0, 1, true).
		AddItem(a.footer, footerHeight, 0, false)

	a.pages = tview.NewPages().AddPage("main", root, true, true)
	a.redraw()

	a.tv.SetRoot(a.pages, true).SetFocus(a.table)
	return a.tv.Run()
}

// refresh recomputes a.merged (full merge) and a.rows (the displayed view)
// — called after every mutation and after any filter/sort/collapse/focus
// state change, since Merge is the single source of truth for StatusNew
// vs. a saved decision vs. StatusResolved.
//
// Exactly one of two "focus" modes narrows the row set beyond the plain
// suppressed/text filters, and they're mutually exclusive (see
// toggleSystemFilter/toggleExpandGroup, which each clear the other):
//   - systemFilter: bypass collapsing, show every finding in one namespace
//     across every policy/Kind — the "study this tenant end-to-end" view.
//   - collapse (default on) + optional expandGroup: apply dedup collapsing
//     (see dedupGroups), then, if expandGroup is set, drill into that one
//     bucket's individual members instead of its collapsed row.
func (a *app) refresh() {
	a.merged = triage.Merge(a.all, a.suppressed, a.state, time.Now())

	rows := a.merged
	if !a.showSuppressed {
		visible := make([]triage.Row, 0, len(rows))
		for _, r := range rows {
			if !r.Suppressed {
				visible = append(visible, r)
			}
		}
		rows = visible
	}

	a.dedupMembers = map[string][]triage.Row{}
	switch {
	case a.systemFilter != "":
		narrowed := make([]triage.Row, 0, len(rows))
		for _, r := range rows {
			if systemOf(r.Entry.Resource) == a.systemFilter {
				narrowed = append(narrowed, r)
			}
		}
		rows = narrowed
	case a.collapse:
		collapsedRows, members := dedupGroups(rows, a.dedupThreshold)
		a.dedupMembers = members
		if a.expandGroup != "" {
			expanded := make([]triage.Row, 0)
			for _, r := range rows {
				if r.Finding != nil && dedupKey(r) == a.expandGroup {
					expanded = append(expanded, r)
				}
			}
			if len(expanded) > 0 {
				rows = expanded
			} else {
				// The expanded bucket no longer exists (e.g. every member
				// got triaged off the active list) — fall back to the
				// collapsed view instead of showing a stale, now-empty
				// drill-down.
				a.expandGroup = ""
				rows = collapsedRows
			}
		} else {
			rows = collapsedRows
		}
	}

	rows = filterRows(rows, a.filter)

	counts := make(map[string]int, len(a.dedupMembers))
	for id, members := range a.dedupMembers {
		counts[id] = len(members)
	}
	filtered := make([]triage.Row, len(rows))
	copy(filtered, rows)
	sortRows(filtered, a.sortField, a.sortAsc, counts)
	a.rows = filtered
}

// systemOf identifies the "system" a resource belongs to for the 's'
// isolate view: its Namespace, or (for a cluster-scoped resource, e.g. the
// Namespace object itself) its own Name.
func systemOf(ref findings.ResourceRef) string {
	if ref.Namespace != "" {
		return ref.Namespace
	}
	return ref.Name
}

func filterRows(rows []triage.Row, q string) []triage.Row {
	if q == "" {
		return rows
	}
	q = strings.ToLower(q)
	out := make([]triage.Row, 0, len(rows))
	for _, r := range rows {
		hay := strings.ToLower(r.Entry.PolicyID + " " + r.Entry.Title + " " + r.Entry.Resource.String())
		if r.Finding != nil {
			hay += " " + strings.ToLower(r.Finding.Message)
		}
		if strings.Contains(hay, q) {
			out = append(out, r)
		}
	}
	return out
}

func nsNameLabel(ref findings.ResourceRef) string {
	if ref.Namespace == "" {
		return ref.Name
	}
	return ref.Namespace + "/" + ref.Name
}

// displayStatus renders StatusNew as "new" explicitly rather than an empty
// cell — an empty status column reads as "not loaded" more than "not yet
// triaged" at a glance.
func displayStatus(e triage.Entry) triage.Status {
	if e.Status == "" {
		return triage.StatusNew
	}
	return e.Status
}

func (a *app) selectedRow() (triage.Row, bool) {
	row, _ := a.table.GetSelection()
	idx := row - 1
	if idx < 0 || idx >= len(a.rows) {
		return triage.Row{}, false
	}
	return a.rows[idx], true
}

// markedOrSelectedTargets returns every row an action should apply to:
// every marked row (if any), else just the current selection — expanded to
// its full dedup bucket if it's a collapsed representative row (see
// expandIfCollapsed), so acting on a collapsed row affects every finding
// it stands for. a.marked itself always holds real, already-expanded
// FindingIDs (toggleMark expands at mark-time), so the marked branch needs
// no further expansion. Rows with no live Finding (resolved) are always
// excluded — nothing left to act on.
func (a *app) markedOrSelectedTargets() []triage.Row {
	var out []triage.Row
	if len(a.marked) > 0 {
		for _, r := range a.merged {
			if r.Finding != nil && a.marked[r.Entry.FindingID] {
				out = append(out, r)
			}
		}
		return out
	}
	if sel, ok := a.selectedRow(); ok && sel.Finding != nil {
		out = append(out, a.expandIfCollapsed(sel)...)
	}
	return out
}

// expandIfCollapsed returns r's full dedup bucket (see dedupGroups) if r is
// a collapsed representative row, else just []triage.Row{r}.
func (a *app) expandIfCollapsed(r triage.Row) []triage.Row {
	if members, ok := a.dedupMembers[r.Entry.FindingID]; ok {
		return members
	}
	return []triage.Row{r}
}

// isFullyMarked reports whether every finding r stands for is marked —
// just a.marked[r.Entry.FindingID] for a normal row, but for a collapsed
// representative row, true only once every member is marked (what the MARK
// column's "●" indicator reflects).
func (a *app) isFullyMarked(r triage.Row) bool {
	members, collapsed := a.dedupMembers[r.Entry.FindingID]
	if !collapsed {
		return a.marked[r.Entry.FindingID]
	}
	for _, m := range members {
		if !a.marked[m.Entry.FindingID] {
			return false
		}
	}
	return true
}

func (a *app) save() {
	a.saveErr = triage.SaveState(a.statePath, a.state)
}

func (a *app) quit() {
	a.save()
	a.tv.Stop()
}

func statusForKey(r rune) triage.Status {
	switch unicode.ToLower(r) {
	case 'c':
		return triage.StatusConfirmed
	case 'x':
		return triage.StatusFalsePositive
	case 'w':
		return triage.StatusWontFix
	case 'd':
		return triage.StatusDuplicate
	case 'i':
		return triage.StatusNeedsInfo
	}
	return ""
}

func (a *app) applyStatus(status triage.Status) {
	targets := a.markedOrSelectedTargets()
	if len(targets) == 0 || status == "" {
		return
	}
	a.confirmBulkAction(fmt.Sprintf("Mark as %s?", status), targets, func() {
		now := time.Now()
		for _, r := range targets {
			_ = a.state.SetStatus(*r.Finding, status, now)
		}
		a.statusLine = fmt.Sprintf("Marked %d finding(s) as %s.", len(targets), status)
		a.marked = map[string]bool{}
		a.save()
		a.refresh()
		a.redraw()
	})
}

// toggleMark marks/unmarks every finding the current row stands for — just
// itself for a normal row, its whole dedup bucket for a collapsed
// representative row (see expandIfCollapsed), so one Space always means
// "select this thing I'm looking at," collapsed or not. A partially-marked
// bucket is treated as unmarked (pressing Space marks the rest) rather than
// flapping between partial states.
// resetToNew undoes a previous triage decision (c/x/w/d/i), reverting the
// marked/selected finding(s) back to "new" — see triage.State.ResetStatus.
// Goes through the same confirmBulkAction gate as applyStatus, since this
// is just as capable of silently touching more findings than intended.
func (a *app) resetToNew() {
	targets := a.markedOrSelectedTargets()
	if len(targets) == 0 {
		return
	}
	a.confirmBulkAction("Reset to new (undo the triage decision)?", targets, func() {
		now := time.Now()
		for _, r := range targets {
			a.state.ResetStatus(*r.Finding, now)
		}
		a.statusLine = fmt.Sprintf("Reset %d finding(s) to new.", len(targets))
		a.marked = map[string]bool{}
		a.save()
		a.refresh()
		a.redraw()
	})
}

func (a *app) toggleMark() {
	sel, ok := a.selectedRow()
	if !ok || sel.Finding == nil {
		return
	}
	members := a.expandIfCollapsed(sel)
	mark := !a.isFullyMarked(sel)
	for _, m := range members {
		if mark {
			a.marked[m.Entry.FindingID] = true
		} else {
			delete(a.marked, m.Entry.FindingID)
		}
	}
	a.redraw()
}

// markVisible marks every row currently shown in a.rows — a "select
// everything I'm looking at" bulk primitive that works the same way in
// every view mode (raw, collapsed, expanded group, isolated system).
// Collapsing being on by default already means a single Space on one
// collapsed row marks its whole duplicate cluster, so this replaces the
// old GroupKey-based "mark similar" with something more broadly useful.
func (a *app) markVisible() {
	for _, r := range a.rows {
		if r.Finding != nil {
			for _, m := range a.expandIfCollapsed(r) {
				a.marked[m.Entry.FindingID] = true
			}
		}
	}
	a.redraw()
}

func (a *app) clearMarks() {
	a.marked = map[string]bool{}
	a.redraw()
}

// toggleCollapse flips whether dedup collapsing (see dedupGroups) is
// applied at all — 'r' (roll up). Off shows every individual finding, the
// pre-collapse flat list.
func (a *app) toggleCollapse() {
	a.collapse = !a.collapse
	a.expandGroup = ""
	a.refresh()
	a.redraw()
}

// toggleExpandGroup drills into the selected row's dedup bucket (see
// dedupGroups), showing its individual members instead of the collapsed
// row — 'g'. Pressing 'g' again (or esc) re-collapses. A no-op with a
// footer note if the selected row isn't actually a collapsed
// representative — nothing hidden to reveal.
func (a *app) toggleExpandGroup() {
	if a.expandGroup != "" {
		a.expandGroup = ""
		a.refresh()
		a.redraw()
		return
	}
	sel, ok := a.selectedRow()
	if !ok || sel.Finding == nil {
		return
	}
	if _, collapsed := a.dedupMembers[sel.Entry.FindingID]; !collapsed {
		a.statusLine = "Nothing collapsed here to expand."
		a.redraw()
		return
	}
	a.expandGroup = dedupKey(sel)
	a.systemFilter = ""
	a.refresh()
	a.redraw()
}

// toggleSystemFilter isolates the table to every finding in the selected
// row's namespace (or exact resource Name for a cluster-scoped resource —
// see systemOf), across every policy and Kind — 's', for reviewing one
// tenant/system end-to-end regardless of which check flagged what.
// Bypasses collapsing entirely (see refresh) since exhaustiveness is the
// point here. Pressing 's' again (or esc) clears it.
func (a *app) toggleSystemFilter() {
	if a.systemFilter != "" {
		a.systemFilter = ""
		a.refresh()
		a.redraw()
		return
	}
	sel, ok := a.selectedRow()
	if !ok {
		return
	}
	a.systemFilter = systemOf(sel.Entry.Resource)
	a.expandGroup = ""
	a.refresh()
	a.redraw()
}

func (a *app) handleKey(event *tcell.EventKey) *tcell.EventKey {
	switch event.Key() {
	case tcell.KeyEnter:
		a.openDetail()
		return nil
	case tcell.KeyEscape:
		if len(a.marked) > 0 {
			a.clearMarks()
			return nil
		}
		if a.expandGroup != "" {
			a.toggleExpandGroup()
			return nil
		}
		if a.systemFilter != "" {
			a.toggleSystemFilter()
			return nil
		}
		return event
	case tcell.KeyRune:
		switch r := event.Rune(); {
		case r == '/':
			a.tv.SetFocus(a.search)
			return nil
		case r == ' ':
			a.toggleMark()
			return nil
		case r == 'a':
			a.markVisible()
			return nil
		case r == 'r':
			a.toggleCollapse()
			return nil
		case r == 'g':
			a.toggleExpandGroup()
			return nil
		case r == 's':
			a.toggleSystemFilter()
			return nil
		case r == 'u':
			a.showSuppressed = !a.showSuppressed
			a.refresh()
			a.redraw()
			return nil
		case r == 'q':
			a.quit()
			return nil
		case r == '?':
			a.openHelp()
			return nil
		case r == 'n':
			a.openNoteEditor()
			return nil
		case r == 't':
			a.openTagsEditor()
			return nil
		case r == 'j':
			a.createJiraIssues()
			return nil
		case r == '0':
			a.resetToNew()
			return nil
		case statusForKey(r) != "":
			a.applyStatus(statusForKey(r))
			return nil
		default:
			if field, ok := sortFieldForDigit(r); ok {
				if a.sortField == field {
					a.sortAsc = !a.sortAsc
				} else {
					a.sortField = field
					a.sortAsc = false
				}
				a.refresh()
				a.redraw()
				return nil
			}
		}
	}
	return event
}
