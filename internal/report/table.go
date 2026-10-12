package report

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/ivanhahanov/kubectl-audit/internal/compliance"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

// This file renders the aggregate-statistics tables (severity breakdown,
// per-check counts, compliance scorecard) that RenderConsole appends
// after its per-finding listing — these used to be a separate --output
// table=... format, folded into console so a CI run has exactly one
// stdout format to reach for instead of two differently-shaped ones (see
// RenderConsole's doc comment for why).
//
// Per-column bounds the per-check table's width-budget split respects —
// see checkTableColumnWidths. POLICY/CONTROLS have no competing free-text
// column to protect here (this table is statistics, not per-finding
// detail — that's RenderConsole's own listing above these tables), so
// they're capped only to guard against one pathological long value, not
// fought over.
const (
	severityColWidth = 8 // len("CRITICAL"), the longest severity
	countColWidth    = 5 // len("COUNT"); actual counts are always shorter
	maxPolicyWidth   = 60
	maxControlsWidth = 40
)

// severityOrder is most-severe-first, matching findings.SortBySeverity's
// own ordering convention used everywhere else in this package.
var severityOrder = []findings.Severity{
	findings.SeverityCritical, findings.SeverityHigh, findings.SeverityMedium,
	findings.SeverityLow, findings.SeverityInfo,
}

// writeSeverityTable renders every severity level (even ones with zero
// findings, for a complete picture at a glance — this isn't a column a
// long tail could blow out) and its count.
func writeSeverityTable(buf *bytes.Buffer, r Result, color bool) {
	summary := r.Summary()
	widths := []int{severityColWidth, countColWidth}
	writeTableBorder(buf, widths, '┌', '┬', '┐')
	writeTableRow(buf, []string{"SEVERITY", "COUNT"}, widths, false, "")
	writeTableBorder(buf, widths, '├', '┼', '┤')
	for _, sev := range severityOrder {
		writeTableRow(buf, []string{string(sev), fmt.Sprintf("%d", summary[sev])}, widths, color, sev)
	}
	writeTableBorder(buf, widths, '└', '┴', '┘')
}

// checkRow is every finding sharing the same check (PolicyID) — unlike
// RenderConsole's finer-grained grouping (also by normalized message),
// a stats table only needs "how many findings did this check produce in
// total", so grouping by PolicyID alone is both simpler and the more
// natural answer to "сколько сработок" per check.
type checkRow struct {
	severity findings.Severity
	policyID string
	controls string
	count    int
}

// writeCheckTable renders one row per check, severity-sorted first and
// by count (most frequent first) within the same severity — the biggest
// contributors to a severity bucket are the ones most worth looking at
// first. CONTROLS cites each check's control ID(s) (see controlIDs — bare
// IDs, not the full "<Framework>: <ID> — <Title>" citation, for the same
// column-width reason as this package's previous table design) and is
// omitted entirely (not just blank) when no framework was requested.
func writeCheckTable(buf *bytes.Buffer, r Result, color bool) {
	controlIndex := buildControlIndex(r.Frameworks)
	showControls := len(r.Frameworks) > 0

	index := map[string]int{}
	var rows []*checkRow
	for _, f := range r.Findings {
		if i, ok := index[f.PolicyID]; ok {
			rows[i].count++
			continue
		}
		index[f.PolicyID] = len(rows)
		rows = append(rows, &checkRow{
			severity: f.Severity,
			policyID: f.PolicyID,
			controls: controlIDs(f, controlIndex),
			count:    1,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].severity != rows[j].severity {
			return rows[i].severity.Rank() > rows[j].severity.Rank()
		}
		return rows[i].count > rows[j].count
	})

	policyNatural, controlsNatural := len("POLICY"), len("CONTROLS")
	for _, row := range rows {
		if w := utf8.RuneCountInString(row.policyID); w > policyNatural {
			policyNatural = w
		}
		if w := utf8.RuneCountInString(row.controls); w > controlsNatural {
			controlsNatural = w
		}
	}
	policyW := min(policyNatural, maxPolicyWidth)
	controlsW := min(controlsNatural, maxControlsWidth)

	headers := []string{"POLICY", "SEVERITY", "COUNT"}
	widths := []int{policyW, severityColWidth, countColWidth}
	if showControls {
		headers = append(headers, "CONTROLS")
		widths = append(widths, controlsW)
	}
	writeTableBorder(buf, widths, '┌', '┬', '┐')
	writeTableRow(buf, headers, widths, false, "")
	writeTableBorder(buf, widths, '├', '┼', '┤')
	for _, row := range rows {
		cells := []string{truncateCell(row.policyID, policyW), string(row.severity), fmt.Sprintf("%d", row.count)}
		if showControls {
			cells = append(cells, truncateCell(row.controls, controlsW))
		}
		writeTableRow(buf, cells, widths, color, row.severity)
	}
	writeTableBorder(buf, widths, '└', '┴', '┘')
}

// writeComplianceTable renders one row per loaded framework via
// compliance.Summarize — the exact same pass/fail/not_applicable/
// not_implemented counts `scan`'s own stdout summary line prints, just
// tabular.
func writeComplianceTable(buf *bytes.Buffer, r Result) {
	headers := []string{"FRAMEWORK", "PASS", "FAIL", "N/A", "NOT_IMPL"}
	frameworkW := len("FRAMEWORK")
	summaries := compliance.Summarize(r.Frameworks)
	for _, s := range summaries {
		label := fmt.Sprintf("%s (%s)", s.Title, s.ID)
		if w := utf8.RuneCountInString(label); w > frameworkW {
			frameworkW = w
		}
	}
	widths := []int{frameworkW, 4, 4, 4, 8}
	writeTableBorder(buf, widths, '┌', '┬', '┐')
	writeTableRow(buf, headers, widths, false, "")
	writeTableBorder(buf, widths, '├', '┼', '┤')
	for _, s := range summaries {
		label := fmt.Sprintf("%s (%s)", s.Title, s.ID)
		cells := []string{
			label,
			fmt.Sprintf("%d", s.Pass),
			fmt.Sprintf("%d", s.Fail),
			fmt.Sprintf("%d", s.NotApplicable),
			fmt.Sprintf("%d", s.NotImplemented),
		}
		writeTableRow(buf, cells, widths, false, "")
	}
	writeTableBorder(buf, widths, '└', '┴', '┘')
}

// truncateCell shortens s to at most max runes, replacing the last
// character with "…" when it had to cut — never splits so aggressively
// that the ellipsis alone would exceed max.
func truncateCell(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	if max <= 1 {
		return string(r[:max])
	}
	return string(r[:max-1]) + "…"
}

func writeTableBorder(buf *bytes.Buffer, widths []int, left, mid, right rune) {
	buf.WriteRune(left)
	for i, w := range widths {
		buf.WriteString(strings.Repeat("─", w+2))
		if i < len(widths)-1 {
			buf.WriteRune(mid)
		}
	}
	buf.WriteRune(right)
	buf.WriteByte('\n')
}

// writeTableRow pads every cell to its column's width, then — only for a
// data row (severity != "") and only when that specific cell's text
// equals the severity string — colors the already-padded text, so the
// ANSI bytes never factor into alignment. Matching on content (not a
// fixed column index) since different tables put the SEVERITY column in
// different positions.
func writeTableRow(buf *bytes.Buffer, cells []string, widths []int, color bool, severity findings.Severity) {
	buf.WriteString("│ ")
	for i, c := range cells {
		padded := c + strings.Repeat(" ", widths[i]-utf8.RuneCountInString(c))
		if color && severity != "" && c == string(severity) {
			if code, ok := ansiBySeverity[severity]; ok {
				padded = code + padded + ansiReset
			}
		}
		buf.WriteString(padded)
		if i < len(cells)-1 {
			buf.WriteString(" │ ")
		}
	}
	buf.WriteString(" │\n")
}
