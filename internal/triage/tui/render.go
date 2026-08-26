package tui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

func (a *app) redraw() {
	a.header.SetText(a.headerText())
	a.redrawTable()
	a.footer.SetText(a.footerText())
}

// headerText builds a compact status board: a colored title bar, then two
// lines of live counts computed from the FULL row set (a.merged), not the
// filtered/sorted view — so the totals stay a trustworthy "here's
// everything" reference even while filtering down to a subset.
func (a *app) headerText() string {
	counts := map[triage.Status]int{}
	sevCounts := map[string]int{}
	suppressedCount := 0
	for _, r := range a.merged {
		counts[statusOf(r)]++
		if r.Suppressed {
			suppressedCount++
		}
		if sev := severityOf(r); sev != "" {
			sevCounts[sev]++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[%s:%s:b] kubectl-audit triage [-:-:-]  [%s]%s[-]\n",
		colorTag(theme.titleFg), colorTag(theme.titleBg), colorTag(theme.dim), a.target)
	fmt.Fprintf(&b, "[%s]findings[-] %s   [%s]state[-] %s\n",
		colorTag(theme.accent), a.findingsPath, colorTag(theme.accent), a.statePath)
	fmt.Fprintf(&b, "[%s]total[-] %d   [yellow]new %d[-]  [red]confirmed %d[-]  false-pos %d  wont-fix %d  dup %d  needs-info %d  "+
		"[green]resolved %d[-]  [%s]suppressed(hidden) %d[-]\n",
		colorTag(theme.accent), len(a.merged), counts[triage.StatusNew], counts[triage.StatusConfirmed],
		counts[triage.StatusFalsePositive], counts[triage.StatusWontFix], counts[triage.StatusDuplicate],
		counts[triage.StatusNeedsInfo], counts[triage.StatusResolved], colorTag(statusColor(statusSuppressed)), suppressedCount)
	fmt.Fprintf(&b, "[red]■[-] critical %d   [orange]■[-] high %d   [yellow]■[-] medium %d   [green]■[-] low %d",
		sevCounts["CRITICAL"], sevCounts["HIGH"], sevCounts["MEDIUM"], sevCounts["LOW"])
	return b.String()
}

func colorTag(c tcell.Color) string {
	r, g, b := c.RGB()
	return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}

// redrawTable renders every visible cell pre-padded to a fixed character
// width (see columnWidths/fixedWidth) rather than relying on
// tview.Table's own auto-sizing (which fits each column to its widest
// CURRENTLY VISIBLE cell) — that's what stops columns from visibly
// resizing as you scroll or filter to a differently-shaped subset of
// rows. No per-row background color either (a flat, non-alternating
// background reads calmer over a wide table than zebra-striping did).
func (a *app) redrawTable() {
	widths := effectiveColumnWidths(a.termWidth)

	a.table.Clear()
	for c := 0; c < columnCount; c++ {
		label := columnLabels[c]
		if c != colMark && sortField(c) == a.sortField {
			if a.sortAsc {
				label += " ▲"
			} else {
				label += " ▼"
			}
		}
		a.table.SetCell(0, c, tview.NewTableCell(fixedWidth(label, widths[c])).
			SetSelectable(false).
			SetTextColor(theme.tableHeaderFg).
			SetBackgroundColor(theme.tableHeaderBg).
			SetAttributes(tcell.AttrBold))
	}

	for i, r := range a.rows {
		row := i + 1

		mark := " "
		if r.Finding != nil && a.isFullyMarked(r) {
			mark = "●"
		}
		sev := severityOf(r)
		sevDisplay := sev
		if sevDisplay == "" {
			sevDisplay = "-"
		}
		countDisplay := "-"
		if n := len(a.dedupMembers[r.Entry.FindingID]); n > 0 {
			countDisplay = fmt.Sprintf("×%d", n)
		}

		set := func(col int, text string, fg tcell.Color) {
			a.table.SetCell(row, col, tview.NewTableCell(fixedWidth(text, widths[col])).SetTextColor(fg))
		}
		set(colMark, mark, theme.mark)
		set(colSeverity, sevDisplay, severityColor(sev))
		set(colStatus, shortStatus(statusOf(r)), statusColor(statusOf(r)))
		set(colPolicy, r.Entry.PolicyID, tcell.ColorWhite)
		set(colKind, r.Entry.Resource.Kind, tcell.ColorWhite)
		set(colNamespaceName, nsNameLabel(r.Entry.Resource), tcell.ColorWhite)
		a.table.SetCell(row, colCount, tview.NewTableCell(fixedWidthRight(countDisplay, widths[colCount])).SetTextColor(theme.accent))
		set(colTags, joinTags(r.Entry.Tags), theme.dim)
	}
}

// sectionLabel and keyHint render the footer/full-screen-header's
// color-coded "[section]"/"[key]" chips — shared so the policy stats and
// detail full-screen pages (see showFullScreenPage) can reuse the exact
// same hotkey-hint styling as the main footer.
func sectionLabel(label string) string {
	return fmt.Sprintf("[%s::b] %s [-:-:-]", colorTag(theme.accent), label)
}

func keyHint(k string) string {
	return "[" + colorTag(theme.accent) + "::b]" + k + "[-:-:-]"
}

func (a *app) footerText() string {
	sec := sectionLabel
	key := keyHint

	line1 := sec("nav") + key("↑/↓") + " move  " + key("enter") + " detail  " + key("/") + " search  " + key("p") + " policies  " +
		sec("noise") + key("r") + " collapse  " + key("g") + " expand group  " + key("s") + " isolate system  " +
		sec("select") + key("space") + " mark  " + key("a") + " mark visible  " + key("esc") + " clear  " + key("1-7") + " sort"
	line2 := sec("triage") + key("c/x/w/d/i") + " confirm/false-pos/wont-fix/dup/needs-info  " + key("0") + " reset to new  " +
		key("j") + " Jira ticket  " + key("n") + " note  " + key("t") + " tags  " + key("u") + " suppressed  " +
		key("q") + " quit  " + key("?") + " help"

	status := fmt.Sprintf("[%s]%d/%d shown[-]", colorTag(theme.dim), len(a.rows), len(a.merged))
	if a.collapse {
		status += fmt.Sprintf("  [%s::b]collapsed (r to show every finding)[-:-:-]", colorTag(theme.accent))
	}
	if a.expandGroup != "" {
		status += fmt.Sprintf("  [%s::b]group: %s (g/esc to clear)[-:-:-]", colorTag(theme.accent), dedupKeyLabel(a.expandGroup))
	}
	if a.systemFilter != "" {
		status += fmt.Sprintf("  [%s::b]system: %s (s/esc to clear)[-:-:-]", colorTag(theme.accent), a.systemFilter)
	}
	if a.policyFilter != "" {
		status += fmt.Sprintf("  [%s::b]policy: %s (p/esc to clear)[-:-:-]", colorTag(theme.accent), a.policyFilter)
	}
	if len(a.marked) > 0 {
		status += fmt.Sprintf("  [%s::b]%d marked[-:-:-]", colorTag(theme.mark), len(a.marked))
	}
	if a.statusLine != "" {
		status += "  [green]▸ " + a.statusLine + "[-]"
	}
	if a.saveErr != nil {
		status += fmt.Sprintf("  [red]save failed: %v[-]", a.saveErr)
	}
	return line1 + "\n" + line2 + "\n" + status
}
