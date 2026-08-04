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
	FindingsBySeverity  []SeverityGroup
	FindingsByNamespace []NamespaceGroup
	Frameworks          []compliance.Scorecard
	ConsolidatedSummary []compliance.FrameworkSummary
	RBACModel           []rbac.SubjectModel
}

func newTemplateData(r Result) TemplateData {
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
		FindingsBySeverity:  groups,
		FindingsByNamespace: groupByNamespace(sorted),
		Frameworks:          r.Frameworks,
		ConsolidatedSummary: compliance.Summarize(r.Frameworks),
		RBACModel:           r.RBACModel,
	}
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
		"join":       func(elems []string, sep string) string { return strings.Join(elems, sep) },
		"rfc3339":    func(t time.Time) string { return t.Format(time.RFC3339) },
		"bindingLabels": func(bindings []rbac.BindingRef) []string {
			var out []string
			seen := map[string]bool{}
			for _, b := range bindings {
				label := fmt.Sprintf("%s/%s", b.RoleKind, b.RoleName)
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
