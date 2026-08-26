package tui

import (
	"sort"
	"strings"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

func joinTags(tags []string) string {
	return strings.Join(tags, ",")
}

// Column layout. Column 0 (mark) has no header label and isn't sortable —
// sortField values below line up 1:1 with column indices 1-7, which is
// what the digit hotkeys ('1'-'7') refer to (the header itself just shows
// a ▲/▼ on whichever one is currently active — see render.go).
const (
	colMark = iota
	colSeverity
	colStatus
	colPolicy
	colKind
	colNamespaceName
	colCount
	colTags
	columnCount
)

var columnLabels = [columnCount]string{"", "SEV", "STATUS", "POLICY ID", "KIND", "NAMESPACE/NAME", "COUNT", "TAGS"}

// columnWidths are fixed character widths, not just upper bounds: every
// cell's text is padded/truncated to exactly this width (see fixedWidth),
// so the rendered column width never depends on which rows happen to be
// visible — without this, tview.Table auto-sizes each column to its
// widest CURRENTLY VISIBLE cell, so scrolling or filtering to a
// differently-shaped subset of rows visibly resizes every column on every
// redraw.
var columnWidths = [columnCount]int{1, 8, 10, 42, 13, 42, 7, 22}

// effectiveColumnWidths returns columnWidths with colNamespaceName grown to
// consume whatever terminal width is left over once every other column,
// the inter-column separators tview.Table draws (one rune per column
// boundary), and the table's own left/right border are accounted for —
// otherwise, on a terminal wider than columnWidths' fixed total, the table
// just leaves blank space on the right instead of stretching to fill the
// screen. NAMESPACE/NAME is the column most worth the extra room (resource
// names are what most often get truncated with "…"). termWidth <= 0 (not
// yet known, e.g. the very first redraw before the app's first real draw
// cycle) returns columnWidths unchanged.
func effectiveColumnWidths(termWidth int) [columnCount]int {
	w := columnWidths
	if termWidth <= 0 {
		return w
	}
	fixed := 0
	for i, cw := range columnWidths {
		if i != colNamespaceName {
			fixed += cw
		}
	}
	const separators = columnCount - 1 // tview.Table draws one rune between each column
	const tableBorder = 2              // the table's own left+right border
	available := termWidth - fixed - separators - tableBorder
	if available > w[colNamespaceName] {
		w[colNamespaceName] = available
	}
	return w
}

// shortStatus abbreviates the longest status value (false_positive, 14
// chars — by far the widest STATUS cell) so the column can stay narrow and
// fixed-width without truncating everything else down to an unreadable
// nub. Other statuses are short enough already to show in full.
func shortStatus(s triage.Status) string {
	if s == triage.StatusFalsePositive {
		return "fp"
	}
	return string(s)
}

// fixedWidth right-pads s with spaces to exactly width runes, or truncates
// with a trailing ellipsis if it's longer — the mechanism that keeps every
// column's rendered width constant regardless of content (see
// columnWidths).
func fixedWidth(s string, width int) string {
	r := []rune(s)
	if len(r) == width {
		return s
	}
	if len(r) > width {
		if width <= 1 {
			return string(r[:width])
		}
		return string(r[:width-1]) + "…"
	}
	return s + strings.Repeat(" ", width-len(r))
}

// fixedWidthRight is fixedWidth's left-padding counterpart, for numeric
// columns (right-aligned is the readable convention for numbers).
func fixedWidthRight(s string, width int) string {
	r := []rune(s)
	if len(r) >= width {
		return fixedWidth(s, width)
	}
	return strings.Repeat(" ", width-len(r)) + s
}

type sortField int

const (
	sortSeverity sortField = colSeverity
	sortStatus   sortField = colStatus
	sortPolicy   sortField = colPolicy
	sortKind     sortField = colKind
	sortNS       sortField = colNamespaceName
	sortCount    sortField = colCount
	sortTags     sortField = colTags
)

func sortFieldForDigit(r rune) (sortField, bool) {
	switch r {
	case '1':
		return sortSeverity, true
	case '2':
		return sortStatus, true
	case '3':
		return sortPolicy, true
	case '4':
		return sortKind, true
	case '5':
		return sortNS, true
	case '6':
		return sortCount, true
	case '7':
		return sortTags, true
	}
	return 0, false
}

func severityOf(r triage.Row) string {
	if r.Finding == nil {
		return ""
	}
	return string(r.Finding.Severity)
}

func statusOf(r triage.Row) triage.Status {
	if r.Suppressed {
		return statusSuppressed
	}
	return displayStatus(r.Entry)
}

// statusSuppressed is a display-only pseudo-status (Row.Suppressed is a
// separate bool on the data model — see internal/triage — since a
// suppressed finding can independently carry a real triage decision too;
// this is purely how the STATUS column labels it when no more specific
// decision has been recorded).
const statusSuppressed triage.Status = "suppressed"

// sortRows orders rows by field, direction asc; resolved rows always sort
// last regardless of field, since there's nothing left to act on them and
// mixing them into an active sort is more confusing than useful. counts
// maps a collapsed representative row's Entry.FindingID to its member
// count (see dedupGroups) — the value the COUNT column shows and sortCount
// sorts by; a row absent from counts (nothing collapsed under it) sorts as
// 0.
func sortRows(rows []triage.Row, field sortField, asc bool, counts map[string]int) {
	sort.SliceStable(rows, func(i, j int) bool {
		ri, rj := rows[i], rows[j]
		iResolved, jResolved := ri.Entry.Status == triage.StatusResolved, rj.Entry.Status == triage.StatusResolved
		if iResolved != jResolved {
			return !iResolved
		}
		if iResolved && jResolved {
			return false
		}

		if c := compareField(ri, rj, field, counts); c != 0 {
			if asc {
				return c < 0
			}
			return c > 0
		}
		// Tie-break: severity descending, then resource name — always in
		// this fixed direction regardless of the primary field's own
		// asc/desc, so ties read consistently no matter what you're
		// sorting by.
		if c := compareSeverityDesc(ri, rj); c != 0 {
			return c < 0
		}
		return ri.Entry.Resource.Name < rj.Entry.Resource.Name
	})
}

// compareField returns <0 if a sorts before b in that field's own natural
// ascending order (alphabetical for text fields, low-to-high for numeric
// ones), 0 if equal, >0 otherwise. sortRows applies asc/desc uniformly on
// top of this, so every case here must stay a true ascending comparison —
// baking a "descending by default" convention into one field (e.g.
// severity) here would make the asc/desc toggle backwards for that field
// only, a real bug an earlier version of this function had.
func compareField(a, b triage.Row, field sortField, counts map[string]int) int {
	switch field {
	case sortSeverity:
		ra, rb := findings.ParseSeverity(severityOf(a)).Rank(), findings.ParseSeverity(severityOf(b)).Rank()
		return ra - rb
	case sortCount:
		return counts[a.Entry.FindingID] - counts[b.Entry.FindingID]
	default:
		va, vb := fieldValue(a, field), fieldValue(b, field)
		return strings.Compare(va, vb)
	}
}

func compareSeverityDesc(a, b triage.Row) int {
	ra, rb := findings.ParseSeverity(severityOf(a)).Rank(), findings.ParseSeverity(severityOf(b)).Rank()
	return rb - ra
}

func fieldValue(r triage.Row, field sortField) string {
	switch field {
	case sortStatus:
		return string(statusOf(r))
	case sortPolicy:
		return r.Entry.PolicyID
	case sortKind:
		return r.Entry.Resource.Kind
	case sortNS:
		return nsNameLabel(r.Entry.Resource)
	case sortTags:
		return joinTags(r.Entry.Tags)
	default:
		return ""
	}
}

// policyStat is one row of the 'p' policy stats picker — everything about
// one PolicyID across the full (unfiltered) row set.
type policyStat struct {
	PolicyID  string
	Title     string
	Severity  string
	Count     int
	New       int
	Confirmed int
}

// policyStats tallies rows by PolicyID, sorted by Count descending (the
// noisiest checks — the ones most worth triaging in bulk — first). Title/
// Severity are taken from the first row seen for that policy (uniform by
// construction: both come from the policy/check definition, not the
// individual resource).
func policyStats(rows []triage.Row) []policyStat {
	byID := map[string]*policyStat{}
	var order []string
	for _, r := range rows {
		id := r.Entry.PolicyID
		s, ok := byID[id]
		if !ok {
			s = &policyStat{PolicyID: id, Title: r.Entry.Title, Severity: severityOf(r)}
			byID[id] = s
			order = append(order, id)
		}
		s.Count++
		switch statusOf(r) {
		case triage.StatusNew:
			s.New++
		case triage.StatusConfirmed:
			s.Confirmed++
		}
	}

	out := make([]policyStat, len(order))
	for i, id := range order {
		out[i] = *byID[id]
	}
	sortPolicyStats(out, policySortCount, false)
	return out
}

// policyStatSortField/policyStatHeaders back the 'p' policy stats picker's
// own digit-key sort ('1'-'6'), the same mechanism the main table's '1'-'7'
// uses (see sortField/columnLabels above) — a separate, smaller set since
// the picker's columns aren't the main table's.
type policyStatSortField int

const (
	policySortSeverity policyStatSortField = iota
	policySortPolicyID
	policySortCount
	policySortNew
	policySortConfirmed
	policySortTitle
)

var policyStatHeaders = [...]string{"SEV", "POLICY ID", "COUNT", "NEW", "CONFIRMED", "TITLE"}

func policyStatSortFieldForDigit(r rune) (policyStatSortField, bool) {
	switch r {
	case '1':
		return policySortSeverity, true
	case '2':
		return policySortPolicyID, true
	case '3':
		return policySortCount, true
	case '4':
		return policySortNew, true
	case '5':
		return policySortConfirmed, true
	case '6':
		return policySortTitle, true
	}
	return 0, false
}

// sortPolicyStats sorts stats in place; asc/desc apply uniformly over a
// true ascending comparison from comparePolicyStat, the same convention
// sortRows/compareField use for the main table (see their doc comment for
// why: baking a fixed direction into one field's own comparator makes the
// asc/desc toggle backwards for that field only).
func sortPolicyStats(stats []policyStat, field policyStatSortField, asc bool) {
	sort.SliceStable(stats, func(i, j int) bool {
		c := comparePolicyStat(stats[i], stats[j], field)
		if asc {
			return c < 0
		}
		return c > 0
	})
}

func comparePolicyStat(a, b policyStat, field policyStatSortField) int {
	switch field {
	case policySortSeverity:
		return findings.ParseSeverity(a.Severity).Rank() - findings.ParseSeverity(b.Severity).Rank()
	case policySortPolicyID:
		return strings.Compare(a.PolicyID, b.PolicyID)
	case policySortCount:
		return a.Count - b.Count
	case policySortNew:
		return a.New - b.New
	case policySortConfirmed:
		return a.Confirmed - b.Confirmed
	case policySortTitle:
		return strings.Compare(a.Title, b.Title)
	default:
		return 0
	}
}
