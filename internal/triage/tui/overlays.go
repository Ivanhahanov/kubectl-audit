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
	tv.SetBorder(true).SetTitle(" " + sel.Entry.PolicyID + " (enter/esc to close) ")
	tv.SetText(a.detailText(sel))
	tv.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEnter || event.Key() == tcell.KeyEscape {
			a.closeOverlay("detail")
			return nil
		}
		return event
	})
	a.showModal("detail", tv, 110, 32)
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
	fmt.Fprintf(&b, "[yellow]Title:[white] %s\n\n", f.Title)
	fmt.Fprintf(&b, "[yellow]Message:[white]\n%s\n\n", f.Message)
	if len(f.CIS) > 0 {
		fmt.Fprintf(&b, "[yellow]CIS:[white] %s\n\n", strings.Join(f.CIS, ", "))
	}
	if f.Remediation != "" {
		fmt.Fprintf(&b, "[yellow]Remediation (how to fix, once confirmed):[white]\n%s\n\n", f.Remediation)
	}
	if f.VerificationSteps != "" {
		fmt.Fprintf(&b, "[green::b]Verification steps (confirm it's a true positive first):[white::-]\n%s\n\n", f.VerificationSteps)
	} else {
		b.WriteString("[red]No verification steps recorded for this check — treat with extra caution.[white]\n\n")
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
