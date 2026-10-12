package report

import (
	"bytes"
	"fmt"
	"os"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

// ansiBySeverity are the color codes wrapped around a finding's [SEVERITY]
// tag when color is enabled — red for the two severities that usually gate
// CI (--fail-on high is the default), yellow for medium, cyan for low,
// no color for info (not worth drawing the eye to).
var ansiBySeverity = map[findings.Severity]string{
	findings.SeverityCritical: "\x1b[1;31m", // bold red
	findings.SeverityHigh:     "\x1b[31m",   // red
	findings.SeverityMedium:   "\x1b[33m",   // yellow
	findings.SeverityLow:      "\x1b[36m",   // cyan
}

const ansiReset = "\x1b[0m"

// consoleGroup is every finding sharing the same check (PolicyID) and
// normalized message (MessageBucketKey) — see RenderConsole.
type consoleGroup struct {
	severity    findings.Severity
	policyID    string
	title       string
	message     string
	remediation string
	controls    string
	resources   []string
}

// RenderConsole renders one block per *check* rather than one line per
// finding: a Title/[SEVERITY] header plus every affected resource
// underneath, severity-sorted (most severe first). A flat one-line-per-
// finding list (this package's first cut) reads fine for a handful of
// findings but turns unreadable the moment the same check fires on
// several resources, since this tool's messages run long — the same
// "same check, many resources" shape the Markdown report's own
// namespace-group-threshold collapsing exists for (see markdown.go/
// template.go's checkCollapseThreshold), grouped here with the identical
// key (PolicyID + MessageBucketKey) so the two outputs never disagree on
// what counts as "the same finding, repeated". Resource lists longer than
// maxRepeatExamples are truncated with a "(+N more)" suffix, the same
// convention the Markdown report uses.
//
// kb is r.KnowledgeBase (nil is fine) — the header's Title goes through
// the exact same resolveCheckKB the Markdown report's check headings use,
// so console output localizes the same way: by default
// triage.ResolveKnowledgeBase already merges in the bundled Russian
// knowledge base (see internal/triage/knowledgebase.go's
// DefaultKnowledgeBase), so this is Russian out of the box unless that's
// been overridden. The body line underneath stays Finding.Message
// unconditionally, same as the Markdown report's own "Affected resources"
// detail — Message is the tool's own per-resource technical text (often
// built with string interpolation, e.g. naming the exact ServiceAccount/
// flag involved), never replaced by a knowledge base, which is written
// once for every finding of that check and couldn't contain that detail
// — see findings.KnowledgeBaseEntry.Description's own doc comment.
//
// When r.Frameworks is non-empty (--frameworks was given), each header
// also cites that check's headline control (see primaryStandard) — the
// same answer to "which section does this belong to" the Markdown
// report's PrimaryStandard column gives.
//
// showRemediation, when true, adds a "Remediation: ..." line — resolved
// through the exact same resolveCheckKB report.md's own Remediation
// column uses, so it's just as actionable and localizes the same way
// (Russian by default): a DevOps engineer scanning their own cluster
// needs to know what to actually do about a finding without necessarily
// opening report.md separately or asking a security specialist — see
// the session this was added in for the concrete gap (console used to
// show only Title+Message, never Remediation, even though the knowledge
// base already had it).
//
// The per-finding list is followed by the same aggregate-statistics
// tables a separate --output table=... used to produce on its own
// (severity breakdown, per-check counts, compliance scorecard — see
// writeSeverityTable/writeCheckTable/writeComplianceTable in table.go):
// console used to be one of two different, differently-shaped stdout
// formats a user had to choose between for CI, which read as "too many
// outputs showing different things" — findings first (what to fix,
// right where you're already looking), tables last (the at-a-glance
// numbers, in the position a CI log is actually read from — the tail —
// the same convention `go test`/`pytest` use: detail first, summary
// last).
//
// color wraps just the "[SEVERITY]" tag (and each table's SEVERITY
// cell) in an ANSI code; pass false when writing to a real file or a
// non-terminal, non-CI stdout (see internal/cli's color-enablement
// decision).
func RenderConsole(r Result, color bool, showRemediation bool, kb map[string]findings.KnowledgeBaseEntry) []byte {
	sorted := append([]findings.Finding{}, r.Findings...)
	findings.SortBySeverity(sorted)
	controlIndex := buildControlIndex(r.Frameworks)

	var groups []*consoleGroup
	index := map[string]int{}
	for _, f := range sorted {
		key := f.PolicyID + "\x00" + MessageBucketKey(f)
		resource := f.Resource.Kind + "/" + f.Resource.Name
		if f.Resource.Namespace != "" {
			resource = f.Resource.Kind + "/" + f.Resource.Namespace + "/" + f.Resource.Name
		}
		if i, ok := index[key]; ok {
			groups[i].resources = append(groups[i].resources, resource)
			continue
		}
		title, _, remediation := resolveCheckKB(f, kb)
		if title == "" {
			title = f.Message
		}
		primary, _ := primaryStandard(f, controlIndex, false)
		index[key] = len(groups)
		groups = append(groups, &consoleGroup{
			severity:    f.Severity,
			policyID:    f.PolicyID,
			title:       title,
			message:     f.Message,
			remediation: remediation,
			controls:    primary,
			resources:   []string{resource},
		})
	}

	var buf bytes.Buffer
	for i, g := range groups {
		if i > 0 {
			buf.WriteByte('\n')
		}
		tag := fmt.Sprintf("[%s]", g.severity)
		if color {
			if code, ok := ansiBySeverity[g.severity]; ok {
				tag = code + tag + ansiReset
			}
		}
		fmt.Fprintf(&buf, "%s %s — %s", tag, g.policyID, g.title)
		if g.controls != "" {
			fmt.Fprintf(&buf, " (%s)", g.controls)
		}
		buf.WriteByte('\n')
		if g.message != "" && g.message != g.title {
			fmt.Fprintf(&buf, "  %s\n", g.message)
		}
		if showRemediation && g.remediation != "" {
			fmt.Fprintf(&buf, "  Remediation: %s\n", g.remediation)
		}
		resources := g.resources
		truncated := false
		if len(resources) > maxRepeatExamples {
			truncated = true
			resources = resources[:maxRepeatExamples]
		}
		for _, res := range resources {
			fmt.Fprintf(&buf, "  → %s\n", res)
		}
		if truncated {
			fmt.Fprintf(&buf, "  → (+%d more)\n", len(g.resources)-len(resources))
		}
	}

	if len(groups) > 0 {
		buf.WriteByte('\n')
	}
	buf.WriteString("Findings by severity:\n")
	writeSeverityTable(&buf, r, color)

	buf.WriteString("\nFindings by check:\n")
	writeCheckTable(&buf, r, color)

	if len(r.Frameworks) > 0 {
		buf.WriteString("\nCompliance scorecard:\n")
		writeComplianceTable(&buf, r)
	}
	return buf.Bytes()
}

// WriteConsole writes RenderConsole's output to path, or to os.Stdout when
// path is "-" (the only writer in this package with that convention —
// console output is meant to be read live in a CI job log/terminal, not
// just saved to disk).
func WriteConsole(path string, r Result, color bool, showRemediation bool) error {
	data := RenderConsole(r, color, showRemediation, r.KnowledgeBase)
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
