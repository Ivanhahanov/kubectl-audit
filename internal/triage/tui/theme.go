package tui

import (
	"github.com/gdamore/tcell/v2"

	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

// theme centralizes every color this package uses — one place to retune
// the look instead of color literals scattered across render.go/tui.go.
// Loosely modeled on k9s's default skin: cyan for chrome/structure, a
// blue-background row highlight, severity/status colors that read at a
// glance without needing to parse text.
var theme = struct {
	titleBg, titleFg tcell.Color
	accent           tcell.Color // section labels, key hints
	dim              tcell.Color // secondary/less-important text
	tableHeaderBg    tcell.Color
	tableHeaderFg    tcell.Color
	selectionBg      tcell.Color
	selectionFg      tcell.Color
	mark             tcell.Color
	borderFg         tcell.Color
}{
	titleBg:       tcell.NewRGBColor(0, 95, 135),
	titleFg:       tcell.ColorWhite,
	accent:        tcell.NewRGBColor(0, 215, 255),
	dim:           tcell.NewRGBColor(140, 140, 140),
	tableHeaderBg: tcell.NewRGBColor(0, 60, 90),
	tableHeaderFg: tcell.NewRGBColor(120, 230, 255),
	selectionBg:   tcell.NewRGBColor(0, 135, 175),
	selectionFg:   tcell.ColorBlack,
	mark:          tcell.ColorGold,
	borderFg:      tcell.NewRGBColor(0, 95, 135),
}

func severityColor(sev string) tcell.Color {
	switch sev {
	case "CRITICAL":
		return tcell.ColorRed
	case "HIGH":
		return tcell.NewRGBColor(255, 135, 0)
	case "MEDIUM":
		return tcell.ColorYellow
	case "LOW":
		return tcell.NewRGBColor(90, 200, 90)
	default:
		return theme.dim
	}
}

func statusColor(s triage.Status) tcell.Color {
	switch s {
	case triage.StatusConfirmed:
		return tcell.ColorRed
	case triage.StatusFalsePositive, triage.StatusWontFix, triage.StatusDuplicate:
		return theme.dim
	case triage.StatusResolved:
		return tcell.NewRGBColor(90, 200, 90)
	case triage.StatusNeedsInfo:
		return tcell.ColorYellow
	case statusSuppressed:
		return tcell.NewRGBColor(180, 130, 255)
	default:
		return tcell.ColorWhite
	}
}
