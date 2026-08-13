package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/compliance"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/rbac"
)

//go:embed templates/default.md.tpl
var defaultTemplateSource string

// DefaultTemplate returns the built-in report.md.tpl source, e.g. for
// `kubectl-audit template dump` to give users a starting point to
// customize.
func DefaultTemplate() string {
	return defaultTemplateSource
}

// SeverityGroup is a bucket of findings sharing one severity, in the order
// the report renders them (most severe first).
type SeverityGroup struct {
	Severity findings.Severity
	Findings []findings.Finding
	Checks   []CheckGroup
}

// CheckGroup is every finding for one PolicyID within a SeverityGroup. Title/
// Category/CIS/Remediation are the same for every finding of a given policy
// by construction, so they're hoisted out and shown once instead of once per
// affected resource — the fix for reports where the same VAP-based check
// fires on many near-identical workloads and used to repeat its full message
// and remediation text for each one. UniformMessage carries the shared
// Message text when every finding in the group has the same one (true for
// essentially every VAP-based check, whose message is a static string in the
// policy YAML); it's left empty when messages differ per finding (true for
// native checks like RBAC/PSS/control-plane, whose message is built
// per-resource), in which case each finding's own Message is rendered.
type CheckGroup struct {
	PolicyID       string
	Title          string
	Category       string
	CIS            []string
	Remediation    string
	UniformMessage string
	Findings       []findings.Finding
}

// ResourceGroup is every finding against one resource.
type ResourceGroup struct {
	Resource findings.ResourceRef
	Findings []findings.Finding
}

// NamespaceGroup is every resource-with-findings in one namespace (or
// cluster-scoped resources, when Namespace is ""), for a per-team/per-app
// view of the report instead of the global severity-first one.
type NamespaceGroup struct {
	Namespace string
	Resources []ResourceGroup
}

// TemplateData is everything the report template can render, either
// directly or via the FuncMap helpers below.
type TemplateData struct {
	GeneratedAt         time.Time
	Target              string
	ClusterVersion      string
	Scope               Scope
	PoliciesLoaded      int
	SeverityOrder       []findings.Severity
	Summary             findings.Summary
	TotalFindings       int
	Findings            []findings.Finding
	Suppressed          []SuppressedFinding
	FindingsBySeverity  []SeverityGroup
	FindingsByNamespace []NamespaceGroup
	Frameworks          []compliance.Scorecard
	ConsolidatedSummary []compliance.FrameworkSummary
	RBACModel           []rbac.SubjectModel
	// ReportView is "check", "namespace", or "both" — see
	// Result.ReportView. Controls which of Findings/FindingsBySeverity vs
	// FindingsByNamespace the template renders, so a large report doesn't
	// list every finding twice by default.
	ReportView string
	// NamespaceDetailed is true when FindingsByNamespace is the report's
	// only findings view (ReportView == "namespace") — the template shows
	// full message/remediation there instead of the compact
	// severity+policyID index it uses when the check-grouped view (which
	// already carries that detail) is also present.
	NamespaceDetailed bool
	// MultipleSources is true when this scan's findings actually came from
	// more than one distinct Source (e.g. several files in a directory
	// scan, or --mode both mixing static files with a live cluster). The
	// template only prints each finding's per-resource "(source)" suffix
	// when this is true — with a single source it's always identical to
	// the report's own Target line, repeated on every single finding for
	// no reason.
	MultipleSources bool
}

func newTemplateData(r Result) TemplateData {
	view := r.ReportView
	if view == "" {
		view = "check"
	}
	wantCheck := view == "check" || view == "both"
	wantNamespace := view == "namespace" || view == "both"

	sorted := append([]findings.Finding{}, r.Findings...)
	findings.SortBySeverity(sorted)

	order := []findings.Severity{
		findings.SeverityCritical, findings.SeverityHigh, findings.SeverityMedium,
		findings.SeverityLow, findings.SeverityInfo,
	}

	var groups []SeverityGroup
	var current *SeverityGroup
	for _, f := range sorted {
		if current == nil || current.Severity != f.Severity {
			groups = append(groups, SeverityGroup{Severity: f.Severity})
			current = &groups[len(groups)-1]
		}
		current.Findings = append(current.Findings, f)
	}
	if wantCheck {
		for i := range groups {
			groups[i].Checks = groupByCheck(groups[i].Findings)
		}
	}

	var byNamespace []NamespaceGroup
	if wantNamespace {
		byNamespace = groupByNamespace(sorted)
	}

	return TemplateData{
		GeneratedAt:         r.GeneratedAt,
		Target:              r.Target,
		ClusterVersion:      r.ClusterVersion,
		Scope:               r.Scope,
		PoliciesLoaded:      r.PoliciesLoaded,
		SeverityOrder:       order,
		Summary:             r.Summary(),
		TotalFindings:       len(r.Findings),
		Findings:            sorted,
		Suppressed:          r.Suppressed,
		FindingsBySeverity:  groups,
		FindingsByNamespace: byNamespace,
		Frameworks:          r.Frameworks,
		ConsolidatedSummary: compliance.Summarize(r.Frameworks),
		RBACModel:           r.RBACModel,
		ReportView:          view,
		NamespaceDetailed:   view == "namespace",
		MultipleSources:     r.MultipleSources,
	}
}

// groupByCheck buckets a (severity-scoped) slice of findings by PolicyID,
// preserving first-seen order. See CheckGroup's doc comment for why.
func groupByCheck(sorted []findings.Finding) []CheckGroup {
	var order []string
	byPolicy := map[string][]findings.Finding{}
	for _, f := range sorted {
		if _, ok := byPolicy[f.PolicyID]; !ok {
			order = append(order, f.PolicyID)
		}
		byPolicy[f.PolicyID] = append(byPolicy[f.PolicyID], f)
	}

	out := make([]CheckGroup, 0, len(order))
	for _, id := range order {
		fs := byPolicy[id]
		uniform := fs[0].Message
		for _, f := range fs[1:] {
			if f.Message != uniform {
				uniform = ""
				break
			}
		}
		out = append(out, CheckGroup{
			PolicyID:       id,
			Title:          fs[0].Title,
			Category:       fs[0].Category,
			CIS:            fs[0].CIS,
			Remediation:    fs[0].Remediation,
			UniformMessage: uniform,
			Findings:       fs,
		})
	}
	return out
}

// groupByNamespace buckets findings by namespace (cluster-scoped resources
// share the "" bucket, sorted last) and then by resource within each
// namespace, so a report reader can find everything about one app/team in
// one place instead of hunting across severity- and framework-grouped
// sections. Input must already be sorted by severity; that order is
// preserved within each resource's finding list.
func groupByNamespace(sorted []findings.Finding) []NamespaceGroup {
	type resourceKey struct{ namespace, kind, name string }

	var order []resourceKey
	byResource := map[resourceKey][]findings.Finding{}
	for _, f := range sorted {
		k := resourceKey{f.Resource.Namespace, f.Resource.Kind, f.Resource.Name}
		if _, ok := byResource[k]; !ok {
			order = append(order, k)
		}
		byResource[k] = append(byResource[k], f)
	}

	var nsOrder []string
	seenNS := map[string]bool{}
	nsResources := map[string][]ResourceGroup{}
	for _, k := range order {
		if !seenNS[k.namespace] {
			seenNS[k.namespace] = true
			nsOrder = append(nsOrder, k.namespace)
		}
		fs := byResource[k]
		nsResources[k.namespace] = append(nsResources[k.namespace], ResourceGroup{
			Resource: fs[0].Resource,
			Findings: fs,
		})
	}

	sort.SliceStable(nsOrder, func(i, j int) bool {
		if nsOrder[i] == "" {
			return false
		}
		if nsOrder[j] == "" {
			return true
		}
		return nsOrder[i] < nsOrder[j]
	})

	out := make([]NamespaceGroup, 0, len(nsOrder))
	for _, ns := range nsOrder {
		resources := nsResources[ns]
		sort.SliceStable(resources, func(i, j int) bool {
			if resources[i].Resource.Kind != resources[j].Resource.Kind {
				return resources[i].Resource.Kind < resources[j].Resource.Kind
			}
			return resources[i].Resource.Name < resources[j].Resource.Name
		})
		out = append(out, NamespaceGroup{Namespace: ns, Resources: resources})
	}
	return out
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"escapeCell": escapeCell,
		"orDash":     orDash,
		"slug":       slug,
		"join":       func(elems []string, sep string) string { return strings.Join(elems, sep) },
		"rfc3339":    func(t time.Time) string { return t.Format(time.RFC3339) },
		// bindingLabels names the actual Binding object(s) granting each
		// row's Permissions, not just the Role/ClusterRole they point to —
		// a shared ClusterRole can be bound by several different
		// bindings, and only the binding name tells you which one to
		// edit/delete (same reasoning as the per-finding messages in
		// internal/rbac/leastprivilege.go).
		"bindingLabels": func(bindings []rbac.BindingRef) []string {
			var out []string
			seen := map[string]bool{}
			for _, b := range bindings {
				bindingName := b.BindingName
				if b.BindingNamespace != "" {
					bindingName = b.BindingNamespace + "/" + b.BindingName
				}
				label := fmt.Sprintf("%s %q → %s/%s", b.BindingKind, bindingName, b.RoleKind, b.RoleName)
				if seen[label] {
					continue
				}
				seen[label] = true
				out = append(out, label)
			}
			return out
		},
		"crossRefs": func(c compliance.Control) string {
			if len(c.CrossRefs) == 0 {
				return ""
			}
			keys := make([]string, 0, len(c.CrossRefs))
			for k := range c.CrossRefs {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, strings.ToUpper(k)+": "+strings.Join(c.CrossRefs[k], ", "))
			}
			return strings.Join(parts, "; ")
		},
		"failingControls": func(sc compliance.Scorecard) []compliance.ControlResult {
			var out []compliance.ControlResult
			for _, res := range sc.Results {
				if res.Status == compliance.StatusFail {
					out = append(out, res)
				}
			}
			return out
		},
		"statusNotes": func(sc compliance.Scorecard) []string {
			var notes []string
			for _, res := range sc.Results {
				switch {
				case res.Status == compliance.StatusNotApplicable && res.Control.NAReason != "":
					notes = append(notes, fmt.Sprintf("- **%s (N/A):** %s", res.Control.ID, res.Control.NAReason))
				case res.Status == compliance.StatusNotImplemented && res.Control.Note != "":
					notes = append(notes, fmt.Sprintf("- **%s (Not Implemented):** %s", res.Control.ID, res.Control.Note))
				}
			}
			return notes
		},
	}
}

// RenderMarkdown renders a human-readable audit report. An empty tplSource
// uses the embedded default template; a non-empty one (e.g. loaded from
// --report-template) fully replaces it.
func RenderMarkdown(r Result, tplSource string) (string, error) {
	if tplSource == "" {
		tplSource = defaultTemplateSource
	}
	tpl, err := template.New("report").Funcs(templateFuncs()).Parse(tplSource)
	if err != nil {
		return "", fmt.Errorf("parsing report template: %w", err)
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, newTemplateData(r)); err != nil {
		return "", fmt.Errorf("executing report template: %w", err)
	}
	return buf.String(), nil
}
