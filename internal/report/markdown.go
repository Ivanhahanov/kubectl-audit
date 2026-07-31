package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/cis"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

// RenderMarkdown renders a human-readable audit report.
func RenderMarkdown(r Result) string {
	var b strings.Builder

	b.WriteString("# Kubernetes Security Audit Report\n\n")
	fmt.Fprintf(&b, "- **Generated:** %s\n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Target:** %s\n", r.Target)
	fmt.Fprintf(&b, "- **Policies loaded:** %d\n\n", r.PoliciesLoaded)

	writeSummary(&b, r)
	if r.CIS != nil {
		writeCIS(&b, *r.CIS)
	}
	if len(r.RBACModel) > 0 {
		writeRBACModel(&b, r)
	}
	writeFindings(&b, r)

	return b.String()
}

// WriteMarkdown renders and writes report.md to path.
func WriteMarkdown(path string, r Result) error {
	return os.WriteFile(path, []byte(RenderMarkdown(r)), 0o644)
}

func writeSummary(b *strings.Builder, r Result) {
	summary := r.Summary()
	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n|---|---|\n")
	for _, sev := range []findings.Severity{
		findings.SeverityCritical, findings.SeverityHigh, findings.SeverityMedium,
		findings.SeverityLow, findings.SeverityInfo,
	} {
		fmt.Fprintf(b, "| %s | %d |\n", sev, summary[sev])
	}
	fmt.Fprintf(b, "| **Total** | **%d** |\n\n", len(r.Findings))
}

func writeCIS(b *strings.Builder, sc cis.Scorecard) {
	fmt.Fprintf(b, "## CIS Kubernetes Benchmark Compliance (v%s)\n\n", sc.Version)
	b.WriteString("| Control | Title | Section | Status | Findings |\n|---|---|---|---|---|\n")
	for _, res := range sc.Results {
		count := ""
		if res.Status == cis.StatusFail {
			count = fmt.Sprintf("%d", len(res.Findings))
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n",
			res.Control.ID, escapeCell(res.Control.Title), escapeCell(res.Control.Section), res.Status, count)
	}
	b.WriteString("\n")

	var notes []string
	for _, res := range sc.Results {
		switch {
		case res.Status == cis.StatusNotApplicable && res.Control.NAReason != "":
			notes = append(notes, fmt.Sprintf("- **%s (N/A):** %s", res.Control.ID, res.Control.NAReason))
		case res.Status == cis.StatusNotImplemented && res.Control.Note != "":
			notes = append(notes, fmt.Sprintf("- **%s (Not Implemented):** %s", res.Control.ID, res.Control.Note))
		}
	}
	if len(notes) > 0 {
		b.WriteString(strings.Join(notes, "\n"))
		b.WriteString("\n\n")
	}

	writeFailingControlDetail(b, sc)
}

// writeFailingControlDetail lists the exact resources behind every FAIL
// control, so the report answers "where does it fail" without cross
// referencing findings.json by hand.
func writeFailingControlDetail(b *strings.Builder, sc cis.Scorecard) {
	var failing []cis.ControlResult
	for _, res := range sc.Results {
		if res.Status == cis.StatusFail {
			failing = append(failing, res)
		}
	}
	if len(failing) == 0 {
		return
	}

	b.WriteString("### Failing controls — affected resources\n\n")
	for _, res := range failing {
		fmt.Fprintf(b, "#### %s — %s\n\n", res.Control.ID, escapeCell(res.Control.Title))
		sorted := append([]findings.Finding{}, res.Findings...)
		findings.SortBySeverity(sorted)
		for _, f := range sorted {
			fmt.Fprintf(b, "- **[%s] %s** (%s) — %s\n", f.Severity, f.Resource.String(), f.PolicyID, f.Message)
		}
		b.WriteString("\n")
	}
}

func writeRBACModel(b *strings.Builder, r Result) {
	b.WriteString("## RBAC Role Model\n\n")
	b.WriteString("| Subject | Namespace | Bindings | Permissions | Risk Flags |\n|---|---|---|---|---|\n")
	for _, m := range r.RBACModel {
		var bindings []string
		seen := map[string]bool{}
		for _, bnd := range m.Bindings {
			label := fmt.Sprintf("%s/%s", bnd.RoleKind, bnd.RoleName)
			if seen[label] {
				continue
			}
			seen[label] = true
			bindings = append(bindings, label)
		}
		fmt.Fprintf(b, "| %s/%s | %s | %s | %s | %s |\n",
			m.Subject.Kind, escapeCell(m.Subject.Name), orDash(m.Subject.Namespace),
			escapeCell(strings.Join(bindings, "<br>")),
			escapeCell(strings.Join(m.Permissions, "<br>")),
			escapeCell(strings.Join(m.RiskFlags, "<br>")))
	}
	b.WriteString("\n")
}

func writeFindings(b *strings.Builder, r Result) {
	b.WriteString("## Findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("No findings.\n")
		return
	}

	sorted := append([]findings.Finding{}, r.Findings...)
	findings.SortBySeverity(sorted)

	var currentSev findings.Severity
	for _, f := range sorted {
		if f.Severity != currentSev {
			currentSev = f.Severity
			fmt.Fprintf(b, "### %s\n\n", currentSev)
		}
		fmt.Fprintf(b, "#### [%s] %s\n\n", f.PolicyID, f.Resource.String())
		fmt.Fprintf(b, "- **Category:** %s\n", f.Category)
		if len(f.CIS) > 0 {
			fmt.Fprintf(b, "- **CIS:** %s\n", strings.Join(f.CIS, ", "))
		}
		if f.Source != "" {
			fmt.Fprintf(b, "- **Source:** %s\n", f.Source)
		}
		fmt.Fprintf(b, "- **Message:** %s\n", f.Message)
		if f.Remediation != "" {
			fmt.Fprintf(b, "- **Remediation:** %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}
}

func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
