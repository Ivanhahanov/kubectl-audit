package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

// maxDetailExamples caps how many member labels the detail view lists for
// a collapsed row, matching internal/report's own maxRepeatExamples
// convention for the same kind of "N examples, then …and M more" listing.
const maxDetailExamples = 8

// showModal centers p in a width x height box over the main page — tview
// has no built-in "centered dialog" primitive for arbitrary content (Modal
// is button-driven only), so this is the standard Flex-nesting trick.
func (a *app) showModal(name string, p tview.Primitive, width, height int) {
	modal := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().
			AddItem(nil, 0, 1, false).
			AddItem(p, width, 1, true).
			AddItem(nil, 0, 1, false),
			height, 1, true).
		AddItem(nil, 0, 1, false)
	a.pages.AddPage(name, modal, true, true)
	a.tv.SetFocus(p)
}

func (a *app) closeOverlay(name string) {
	a.pages.RemovePage(name)
	a.pages.SwitchToPage("main")
	a.tv.SetFocus(a.table)
}

// showFullScreenPage replaces the main view with a k9s-style full-screen
// screen: a slim title bar naming the section (plus a one-line hotkey
// hint), then content filling the rest. Used for views that are
// themselves a list/table in their own right — the policy stats picker,
// finding detail — which read as a real screen rather than a small
// floating dialog, the same way k9s never shows a resource list or detail
// view in a popup. closeOverlay(name) (the same one small modals use)
// returns to the main table; nothing about closing differs between the
// two, only how the page is built.
func (a *app) showFullScreenPage(name, title, hint string, content tview.Primitive) {
	header := tview.NewTextView().SetDynamicColors(true)
	header.SetBorder(true).SetBorderColor(theme.borderFg)
	header.SetText(fmt.Sprintf("[%s:%s:b] %s [-:-:-]\n%s",
		colorTag(theme.titleFg), colorTag(theme.titleBg), title, hint))

	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(header, 4, 0, false).
		AddItem(content, 0, 1, true)

	a.pages.AddPage(name, layout, true, true)
	a.tv.SetFocus(content)
}

// confirmBulkAction gates any action that would touch more than one
// finding at once behind an explicit Yes/Cancel — the safeguard against
// silently bulk-triaging (or bulk-Jira-ticketing) findings you only meant
// to act on one of, whether from a collapsed row or a multi-row mark.
// proceed runs immediately, no dialog, when targets has 0 or 1 entries —
// this only guards genuinely bulk actions.
func (a *app) confirmBulkAction(prompt string, targets []triage.Row, proceed func()) {
	if len(targets) <= 1 {
		proceed()
		return
	}
	modal := tview.NewModal().
		SetText(fmt.Sprintf("%s\n\n%d findings will be affected.", prompt, len(targets))).
		AddButtons([]string{"Cancel", "Yes, apply to all"}).
		SetDoneFunc(func(_ int, label string) {
			a.closeOverlay("confirm")
			if label == "Yes, apply to all" {
				proceed()
			}
		})
	modal.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			a.closeOverlay("confirm")
			return nil
		}
		return event
	})
	a.pages.AddPage("confirm", modal, true, true)
	a.tv.SetFocus(modal)
}

// editorTitle builds the modal title for the note/tags editors, appending
// a bulk-apply notice when editing a collapsed representative row applies
// the same text to every finding it stands for (see expandIfCollapsed) —
// that's never supposed to be a silent surprise.
func editorTitle(label string, sel triage.Row, targets []triage.Row) string {
	if len(targets) > 1 {
		return fmt.Sprintf(" %s — %s (applies to all %d collapsed findings) ", label, sel.Entry.PolicyID, len(targets))
	}
	return " " + label + " — " + sel.Entry.PolicyID + " "
}

func (a *app) openNoteEditor() {
	sel, ok := a.selectedRow()
	if !ok || sel.Finding == nil {
		return
	}
	targets := a.expandIfCollapsed(sel)
	input := tview.NewInputField().SetLabel("Note: ").SetText(sel.Entry.Note)
	input.SetBorder(true).SetTitle(editorTitle("Note", sel, targets))
	input.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			a.closeOverlay("note")
			a.redraw()
			return
		}
		text := input.GetText()
		a.closeOverlay("note")
		a.confirmBulkAction(fmt.Sprintf("Set this note on %d findings?", len(targets)), targets, func() {
			now := time.Now()
			for _, t := range targets {
				a.state.SetNote(*t.Finding, text, now)
			}
			a.save()
			a.refresh()
			a.redraw()
		})
	})
	a.showModal("note", input, 80, 3)
}

func (a *app) openTagsEditor() {
	sel, ok := a.selectedRow()
	if !ok || sel.Finding == nil {
		return
	}
	targets := a.expandIfCollapsed(sel)
	input := tview.NewInputField().SetLabel("Tags (comma-separated): ").SetText(strings.Join(sel.Entry.Tags, ", "))
	input.SetBorder(true).SetTitle(editorTitle("Tags", sel, targets))
	input.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			a.closeOverlay("tags")
			a.redraw()
			return
		}
		tags := splitTags(input.GetText())
		a.closeOverlay("tags")
		a.confirmBulkAction(fmt.Sprintf("Set these tags on %d findings?", len(targets)), targets, func() {
			now := time.Now()
			for _, t := range targets {
				a.state.SetTags(*t.Finding, tags, now)
			}
			a.save()
			a.refresh()
			a.redraw()
		})
	})
	a.showModal("tags", input, 80, 3)
}

func splitTags(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (a *app) openDetail() {
	sel, ok := a.selectedRow()
	if !ok {
		return
	}
	tv := tview.NewTextView().SetDynamicColors(true).SetWrap(true).SetScrollable(true)
	tv.SetBorder(true).SetBorderColor(theme.borderFg)
	tv.SetText(a.detailText(sel))
	tv.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEnter || event.Key() == tcell.KeyEscape {
			a.closeOverlay("detail")
			return nil
		}
		return event
	})
	a.showFullScreenPage("detail", "FINDING — "+sel.Entry.PolicyID, keyHint("enter/esc")+" back", tv)
}

func (a *app) detailText(r triage.Row) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[yellow]Resource:[white] %s\n", r.Entry.Resource.String())
	fmt.Fprintf(&b, "[yellow]Status:[white] %s\n", statusOf(r))
	if r.Suppressed {
		fmt.Fprintf(&b, "[purple]Suppressed:[white] %s\n", r.SuppressReason)
	}
	if members := a.dedupMembers[r.Entry.FindingID]; len(members) > 1 {
		fmt.Fprintf(&b, "[yellow]Collapsed:[white] %d findings — same check, same Kind/name-shape, identical message. "+
			"Press 'g' to review (and mark) each one individually.\n", len(members))
		labels := make([]string, 0, len(members))
		for _, m := range members {
			labels = append(labels, nsNameLabel(m.Entry.Resource))
		}
		sort.Strings(labels)
		truncated := len(labels) > maxDetailExamples
		if truncated {
			labels = labels[:maxDetailExamples]
		}
		example := strings.Join(labels, ", ")
		if truncated {
			example += fmt.Sprintf(", …and %d more", len(members)-maxDetailExamples)
		}
		fmt.Fprintf(&b, "  %s\n", example)
	}
	if len(r.Entry.Tags) > 0 {
		fmt.Fprintf(&b, "[yellow]Tags:[white] %s\n", strings.Join(r.Entry.Tags, ", "))
	}
	if r.Entry.Note != "" {
		fmt.Fprintf(&b, "[yellow]Note:[white] %s\n", r.Entry.Note)
	}
	if r.Entry.JiraIssueKey != "" {
		fmt.Fprintf(&b, "[yellow]Jira:[white] %s (%s)\n", r.Entry.JiraIssueKey, r.Entry.JiraIssueURL)
	}
	b.WriteString("\n")

	if r.Finding == nil {
		b.WriteString("[green]This finding is no longer produced by the latest scan — the underlying " +
			"issue appears to have been fixed (or the resource was deleted). No further action needed " +
			"unless you want to double check.[white]\n")
		return b.String()
	}

	f := r.Finding
	// content is exactly what a Jira ticket would show (see
	// triage.Resolve/RenderIssueDescription) — computed the same way here
	// so this view is always a trustworthy preview of what filing a ticket
	// would actually produce. Labels stay constant regardless of whether a
	// knowledge base is involved — it's meant to blend in as the tool's
	// own content, not to be flagged inline every time it applies.
	content, err := triage.Resolve(*f, a.knowledgeBase)
	if err != nil {
		// Surfaced here deliberately: this view is exactly where a
		// broken knowledge-base template (e.g. a typo'd {{ }}) should be
		// caught, before it ever reaches a filed ticket.
		fmt.Fprintf(&b, "[red]Knowledge base template error:[white] %v\n\n", err)
	}

	fmt.Fprintf(&b, "[yellow]Title:[white] %s\n\n", content.Title)
	fmt.Fprintf(&b, "[yellow]Description:[white]\n%s\n\n", content.Description)
	if content.Technical != "" {
		fmt.Fprintf(&b, "[yellow]Technical detail:[white]\n%s\n\n", content.Technical)
	}
	if len(f.CIS) > 0 {
		fmt.Fprintf(&b, "[yellow]CIS:[white] %s\n\n", strings.Join(f.CIS, ", "))
	}
	if content.Remediation != "" {
		fmt.Fprintf(&b, "[yellow]Remediation:[white]\n%s\n\n", content.Remediation)
	}
	return b.String()
}

const helpText = `[yellow::b]kubectl audit triage — hotkeys[white::-]

  [yellow::b]Navigate[white::-]
  up/down, pgup/pgdn    move
  enter                 open finding detail
  /                     focus the search bar (live filter over title/policy/resource/message)
  esc                   (in search) clear filter · (in table) clear marks, then clear
                         group-expand/system-isolate, in that order

  [yellow::b]Noise reduction (OFF by default — every finding is its own row until you opt in)[white::-]
  r                      toggle collapsing repeated findings (same check + same Kind, identical
                          message — the safe-to-merge case, e.g. a check firing on 19 differently
                          named Deployments with the exact same message) into one row with a COUNT
  g                      on a collapsed row: expand it to review (and act on) each individual
                          finding — press again (or esc) to re-collapse
  s                      isolate the table to every finding in this row's namespace, across every
                          check and resource Kind — for reviewing one tenant/system end-to-end.
                          Bypasses collapsing. Press again (or esc) to clear.
  p                      policy stats: every check with severity/count/new/confirmed — sorted by
                          count by default, press 1-6 to sort by another column (again to reverse)
                          — enter on one to filter the table to just that policy (press 'p' again,
                          or esc, to clear)

  [yellow::b]Sort[white::-]
  1-7                   sort by that column (shown as "N:LABEL" in the header) — press again to
                         reverse direction

  [yellow::b]Select[white::-]
  space                 mark/unmark the current row — its whole dedup bucket if it's collapsed
  a                     mark every row currently visible (whatever view mode is active)

  [yellow::b]Triage decisions (apply to every marked row, or the selected row if none marked —[white::-]
  [yellow::b]expanded to every finding a collapsed row stands for. Anything touching more than one[white::-]
  [yellow::b]finding at once asks "Yes / Cancel" first — nothing bulk-applies silently.)[white::-]
  c                      confirmed
  x                      false positive
  w                      won't fix
  d                      duplicate
  i                      needs more info
  0                      reset back to new (undo a previous c/x/w/d/i)
  n                      edit note (same bulk-apply rule)
  t                      edit tags, comma-separated (same bulk-apply rule)
  j                      create a Jira ticket for every marked/selected CONFIRMED finding without
                         one yet (needs triage.jira configured — see docs/triage.md)

  [yellow::b]Other[white::-]
  u                      show/hide suppressed findings (hidden by default)
  q                      save and quit
  ?                      this help (any key closes)

State autosaves after every action.
`

func (a *app) openHelp() {
	tv := tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	tv.SetBorder(true).SetTitle(" Help ")
	tv.SetText(helpText)
	tv.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		a.closeOverlay("help")
		return nil
	})
	a.showModal("help", tv, 90, 30)
}

// openPolicyStats shows every PolicyID present in the full row set
// (a.merged — not narrowed by any current filter, so it's always a
// trustworthy "everything" overview), tallied by policyStats. Sortable by
// column with '1'-'6' (same digit-key-plus-▲/▼-indicator convention as the
// main table's '1'-'7' — see sortField/redrawTable), persisted in
// a.policySortField/policySortAsc across opens. Enter on a row sets
// a.policyFilter to that PolicyID and returns to the main table narrowed to
// it (see togglePolicyFilter); esc closes without picking anything.
func (a *app) openPolicyStats() {
	stats := policyStats(a.merged)
	if len(stats) == 0 {
		a.statusLine = "No findings to show policy stats for."
		a.redraw()
		return
	}
	sortPolicyStats(stats, a.policySortField, a.policySortAsc)

	t := tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	t.SetSelectedStyle(tcell.StyleDefault.Background(theme.selectionBg).Foreground(theme.selectionFg).Bold(true))
	t.SetBorder(true).SetBorderColor(theme.borderFg)

	render := func() {
		t.Clear()
		for c, h := range policyStatHeaders {
			label := h
			if policyStatSortField(c) == a.policySortField {
				if a.policySortAsc {
					label += " ▲"
				} else {
					label += " ▼"
				}
			}
			t.SetCell(0, c, tview.NewTableCell(label).
				SetSelectable(false).
				SetTextColor(theme.tableHeaderFg).
				SetBackgroundColor(theme.tableHeaderBg).
				SetAttributes(tcell.AttrBold))
		}
		for i, s := range stats {
			row := i + 1
			set := func(col int, text string, fg tcell.Color, align int) {
				t.SetCell(row, col, tview.NewTableCell(text).SetTextColor(fg).SetAlign(align))
			}
			set(0, s.Severity, severityColor(s.Severity), tview.AlignLeft)
			set(1, s.PolicyID, tcell.ColorWhite, tview.AlignLeft)
			set(2, fmt.Sprintf("%d", s.Count), theme.accent, tview.AlignRight)
			set(3, fmt.Sprintf("%d", s.New), statusColor(triage.StatusNew), tview.AlignRight)
			set(4, fmt.Sprintf("%d", s.Confirmed), statusColor(triage.StatusConfirmed), tview.AlignRight)
			set(5, s.Title, theme.dim, tview.AlignLeft)
		}
	}
	render()

	t.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEnter:
			if row, _ := t.GetSelection(); row >= 1 && row-1 < len(stats) {
				a.policyFilter = stats[row-1].PolicyID
				a.refresh()
			}
			a.closeOverlay("policyStats")
			a.redraw()
			return nil
		case tcell.KeyEscape:
			a.closeOverlay("policyStats")
			return nil
		case tcell.KeyRune:
			if field, ok := policyStatSortFieldForDigit(event.Rune()); ok {
				if a.policySortField == field {
					a.policySortAsc = !a.policySortAsc
				} else {
					a.policySortField = field
					a.policySortAsc = false
				}
				sortPolicyStats(stats, a.policySortField, a.policySortAsc)
				render()
				return nil
			}
		}
		return event
	})

	a.showFullScreenPage("policyStats", "POLICIES",
		keyHint("enter")+" filter to this policy   "+keyHint("1-6")+" sort   "+keyHint("esc")+" back", t)
}
