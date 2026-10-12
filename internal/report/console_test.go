package report_test

import (
	"strings"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/report"
)

func testConsoleResult() report.Result {
	return report.Result{
		Target: "test",
		Findings: []findings.Finding{
			{ID: "1", PolicyID: "workload.x", Severity: findings.SeverityMedium, Title: "Medium title",
				Resource: findings.ResourceRef{Kind: "Pod", Name: "p", Namespace: "default"}, Message: "medium issue"},
			{ID: "2", PolicyID: "workload.y", Severity: findings.SeverityCritical, Title: "Critical title",
				Resource: findings.ResourceRef{Kind: "Deployment", Name: "d", Namespace: "default"}, Message: "critical issue"},
		},
	}
}

func TestRenderConsole_GroupsBySeverityMostSevereFirst(t *testing.T) {
	out := string(report.RenderConsole(testConsoleResult(), false, true, nil))
	// Each group is header + message + 1 resource line; a blank line
	// separates the CRITICAL group from the MEDIUM group. Only look at
	// the per-finding section — the stats tables appended after it are
	// covered by their own test below.
	findingsSection, _, _ := strings.Cut(out, "Findings by severity:")
	lines := strings.Split(strings.TrimRight(findingsSection, "\n"), "\n")
	if len(lines) != 7 {
		t.Fatalf("expected 7 lines, got %d: %q", len(lines), findingsSection)
	}
	if !strings.HasPrefix(lines[0], "[CRITICAL] workload.y — Critical title") {
		t.Errorf("expected CRITICAL group header first, got %q", lines[0])
	}
	if lines[3] != "" {
		t.Errorf("expected a blank line between groups, got %q", lines[3])
	}
	if !strings.HasPrefix(lines[4], "[MEDIUM] workload.x — Medium title") {
		t.Errorf("expected MEDIUM group header after the separator, got %q", lines[4])
	}
}

func TestRenderConsole_AppendsStatsTablesAfterFindings(t *testing.T) {
	out := string(report.RenderConsole(testConsoleResult(), false, true, nil))
	findingsIdx := strings.Index(out, "[CRITICAL]")
	severityIdx := strings.Index(out, "Findings by severity:")
	checkIdx := strings.Index(out, "Findings by check:")
	if findingsIdx == -1 || severityIdx == -1 || checkIdx == -1 {
		t.Fatalf("expected findings followed by both stats tables, got %q", out)
	}
	if !(findingsIdx < severityIdx && severityIdx < checkIdx) {
		t.Errorf("expected order findings -> severity table -> check table, got %q", out)
	}
	if !strings.Contains(out, "CRITICAL") || !strings.Contains(out, "workload.y") {
		t.Errorf("expected the stats tables to reflect the findings, got %q", out)
	}
}

func TestRenderConsole_NoFindingsStillRendersStatsTables(t *testing.T) {
	out := string(report.RenderConsole(report.Result{}, false, true, nil))
	if !strings.HasPrefix(out, "Findings by severity:") {
		t.Errorf("expected stats tables with no leading blank line when there are no findings, got %q", out)
	}
}

func TestRenderConsole_GroupsSameCheckAcrossResourcesInsteadOfRepeatingTheMessage(t *testing.T) {
	r := report.Result{Findings: []findings.Finding{
		{ID: "1", PolicyID: "workload.z", Severity: findings.SeverityHigh, Title: "t",
			Resource: findings.ResourceRef{Kind: "Pod", Name: "a"}, Message: "same message"},
		{ID: "2", PolicyID: "workload.z", Severity: findings.SeverityHigh, Title: "t",
			Resource: findings.ResourceRef{Kind: "Pod", Name: "b"}, Message: "same message"},
	}}
	out := string(report.RenderConsole(r, false, true, nil))
	if strings.Count(out, "[HIGH]") != 1 {
		t.Errorf("expected exactly one [HIGH] header for the shared check, got %q", out)
	}
	if !strings.Contains(out, "→ Pod/a") || !strings.Contains(out, "→ Pod/b") {
		t.Errorf("expected both resources listed under the shared header, got %q", out)
	}
}

func TestRenderConsole_NoColorHasNoEscapeCodes(t *testing.T) {
	out := string(report.RenderConsole(testConsoleResult(), false, true, nil))
	if strings.Contains(out, "\x1b[") {
		t.Errorf("expected no ANSI escape codes with color=false, got %q", out)
	}
}

func TestRenderConsole_ColorWrapsSeverityTagOnly(t *testing.T) {
	out := string(report.RenderConsole(testConsoleResult(), true, true, nil))
	if !strings.Contains(out, "\x1b[1;31m[CRITICAL]\x1b[0m") {
		t.Errorf("expected colored CRITICAL tag, got %q", out)
	}
	if !strings.Contains(out, "critical issue") {
		t.Errorf("expected message text to survive uncolored, got %q", out)
	}
}

func TestRenderConsole_ShowsRemediationFromKnowledgeBaseWhenEnabled(t *testing.T) {
	kb := map[string]findings.KnowledgeBaseEntry{
		"workload.y": {Remediation: "Do the fix"},
	}
	out := string(report.RenderConsole(testConsoleResult(), false, true, kb))
	if !strings.Contains(out, "Remediation: Do the fix") {
		t.Errorf("expected remediation line from the knowledge base, got %q", out)
	}
}

func TestRenderConsole_OmitsRemediationWhenDisabled(t *testing.T) {
	kb := map[string]findings.KnowledgeBaseEntry{
		"workload.y": {Remediation: "Do the fix"},
	}
	out := string(report.RenderConsole(testConsoleResult(), false, false, kb))
	if strings.Contains(out, "Remediation:") {
		t.Errorf("expected no remediation line when showRemediation=false, got %q", out)
	}
}
