package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/compliance"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/rbac"
	"github.com/ivanhahanov/kubectl-audit/internal/thirdparty"
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
	// Rows is how the template actually renders "Affected resources" when
	// UniformMessage is set: findings.Finding rows verbatim, except a group
	// of findings sharing the same Kind and "name shape" (see nameTemplate)
	// — at least namespaceGroupThreshold of them — collapses into one
	// AffectedRow instead of one row each. Nil (falls back to ranging over
	// Findings, today's behavior) when UniformMessage is empty or
	// collapsing is disabled (threshold <= 0). See AffectedRow and
	// groupAffectedResources.
	Rows []AffectedRow
}

// AffectedRow is one line of a CheckGroup's "Affected resources" list: either
// a single finding, or — when Repeat is set — a collapsed summary of many
// findings sharing a Kind and name shape (the common per-tenant-namespace
// shape, e.g. Capsule-provisioned tenants all deploying the same manifest
// under the same object name into different namespaces, or a per-tenant
// namespace itself named with a generated/UUID suffix). Exactly one of
// Finding/Repeat is set.
type AffectedRow struct {
	Finding *findings.Finding
	Repeat  *RepeatGroup
}

// RepeatGroup summarizes Count findings sharing a Kind and name shape within
// one check — same message (the group's UniformMessage), same resource Kind,
// names either identical or matching the same generated-identifier template
// (see nameTemplate). Unit is "namespaces" when every collapsed finding is a
// namespaced resource (the per-tenant-namespace-deploying-the-same-manifest
// shape — Examples then lists distinct namespaces) or "objects" when they're
// cluster-scoped (e.g. Namespace objects themselves named per-tenant —
// Examples then lists distinct object names, since there's no namespace to
// report). Examples is capped at maxRepeatExamples and sorted; Truncated
// says whether Count exceeds len(Examples).
type RepeatGroup struct {
	Kind         string
	NameTemplate string
	Unit         string
	Count        int
	Examples     []string
	Truncated    bool
}

// maxRepeatExamples caps how many example namespaces/object names a
// collapsed RepeatGroup row prints — a real multi-tenant cluster can have
// thousands of matching namespaces (see the docstring on nameTemplate), and
// printing all of them would defeat the point of collapsing.
const maxRepeatExamples = 8

// uuidPattern matches a canonical 8-4-4-4-12 hex UUID (case-insensitive) —
// by far the most common generated-identifier shape in practice (Capsule
// and similar tools commonly suffix or name tenant namespaces with one).
var uuidPattern = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// longHexRunPattern and longDigitRunPattern catch other generated-identifier
// shapes that aren't a full UUID: a truncated hash/id, a numeric tenant/
// customer ID, etc. The length floors (8 hex chars, 4 digits) are
// deliberately conservative — short numeric segments are common in
// legitimate, hand-chosen names (e.g. "app-v2", a port number) and
// collapsing those together would actively mislead a reader into thinking
// unrelated resources are the same tenant's repeated template.
var (
	longHexRunPattern   = regexp.MustCompile(`(?i)[0-9a-f]{8,}`)
	longDigitRunPattern = regexp.MustCompile(`[0-9]{4,}`)
)

// nameTemplate normalizes a resource name to a "shape" for grouping: runs
// that look like a generated/random identifier are replaced with "*", so
// e.g. "usersvs-0004237b-3813-48ce-a48f-3cabdaeccbea" and
// "usersvs-0006e164-99bc-4fac-aaec-079df475fa6b" (a real shape seen on a
// Capsule-managed cluster, where every tenant gets its own
// "<prefix>-<uuid>" namespace) both normalize to "usersvs-*", while
// hand-chosen names like "argocd" or "cert-manager" — which contain no
// UUID or long hex/digit run — pass through completely unchanged and so
// never accidentally group with anything. A name with no variable-looking
// part at all normalizes to itself, which is exactly what makes plain
// exact-name matching (e.g. the same Deployment name "app" repeated across
// several tenant namespaces) a special case of this same mechanism rather
// than a separate one.
func nameTemplate(name string) string {
	t := uuidPattern.ReplaceAllString(name, "*")
	t = longHexRunPattern.ReplaceAllString(t, "*")
	t = longDigitRunPattern.ReplaceAllString(t, "*")
	return t
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
	// DetectedComponents is Result.DetectedComponents, unchanged — see its
	// doc comment. Rendered as its own report section so a reader can see
	// at a glance what infrastructure this scan recognized and why its
	// built-in exceptions did or didn't apply.
	DetectedComponents []thirdparty.Detection
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
			groups[i].Checks = groupByCheck(groups[i].Findings, r.NamespaceGroupThreshold, r.GroupByNamePattern)
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
		DetectedComponents:  r.DetectedComponents,
	}
}

// groupByCheck buckets a (severity-scoped) slice of findings by PolicyID,
// preserving first-seen order. See CheckGroup's doc comment for why.
// namespaceGroupThreshold and byPattern are forwarded to
// groupAffectedResources for each group's Rows; threshold <= 0 disables
// collapsing (Rows stays nil, template falls back to Findings).
func groupByCheck(sorted []findings.Finding, namespaceGroupThreshold int, byPattern bool) []CheckGroup {
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
		// Always built (not just when collapsing is possible) whenever the
		// message is uniform: the template ranges over Rows for that
		// branch unconditionally, so an empty Rows would render nothing
		// rather than falling back to Findings.
		var rows []AffectedRow
		if uniform != "" {
			rows = groupAffectedResources(fs, namespaceGroupThreshold, byPattern)
		}
		out = append(out, CheckGroup{
			PolicyID:       id,
			Title:          fs[0].Title,
			Category:       fs[0].Category,
			CIS:            fs[0].CIS,
			Remediation:    fs[0].Remediation,
			UniformMessage: uniform,
			Findings:       fs,
			Rows:           rows,
		})
	}
	return out
}

// groupAffectedResources collapses a check's findings into AffectedRows: a
// group of at least threshold findings sharing a Kind and name shape
// collapses into one RepeatGroup row; everything else stays one row per
// finding. The name shape is either the exact Name (byPattern false — the
// same Deployment name "app" repeated across several tenant namespaces is
// the canonical case) or nameTemplate(Name) (byPattern true — additionally
// catches per-tenant resources whose *name itself* is generated, e.g. a
// Namespace named "usersvs-<uuid>" per tenant, which can never share an
// exact Name since Namespace objects are cluster-scoped and uniquely
// named). threshold <= 0 disables collapsing entirely: every finding gets
// its own row, same order as fs (this is also what makes an unset
// Result.NamespaceGroupThreshold — the zero value, so direct report.Result
// literals in tests/other callers get today's pre-collapsing behavior —
// safe).
func groupAffectedResources(fs []findings.Finding, threshold int, byPattern bool) []AffectedRow {
	if threshold <= 0 {
		rows := make([]AffectedRow, len(fs))
		for i := range fs {
			rows[i] = AffectedRow{Finding: &fs[i]}
		}
		return rows
	}

	type key struct{ kind, shape string }

	type bucket struct {
		examples    []string
		seenExample map[string]bool
		count       int
	}
	buckets := map[key]*bucket{}
	var order []key
	for _, f := range fs {
		shape := f.Resource.Name
		if byPattern {
			shape = nameTemplate(f.Resource.Name)
		}
		k := key{f.Resource.Kind, shape}
		b, ok := buckets[k]
		if !ok {
			b = &bucket{seenExample: map[string]bool{}}
			buckets[k] = b
			order = append(order, k)
		}
		b.count++
		// The identifying label: which namespace, for a namespaced
		// resource sharing one object name across tenants; which object
		// name, for a cluster-scoped resource (or a namespaced one whose
		// own name is what varies) — whichever one actually varies across
		// this bucket's members.
		label := f.Resource.Namespace
		if label == "" {
			label = f.Resource.Name
		}
		if !b.seenExample[label] {
			b.seenExample[label] = true
			b.examples = append(b.examples, label)
		}
	}

	// Only buckets meeting the threshold actually collapse; everything else
	// renders as an individual row.
	collapse := map[key]*bucket{}
	for _, k := range order {
		if b := buckets[k]; b.count >= threshold {
			collapse[k] = b
		}
	}

	rows := make([]AffectedRow, 0, len(fs))
	inRepeat := map[key]bool{}
	for i, f := range fs {
		shape := f.Resource.Name
		if byPattern {
			shape = nameTemplate(f.Resource.Name)
		}
		k := key{f.Resource.Kind, shape}
		b, isRepeat := collapse[k]
		if !isRepeat {
			rows = append(rows, AffectedRow{Finding: &fs[i]})
			continue
		}
		if inRepeat[k] {
			continue // already emitted this repeat group's row
		}
		inRepeat[k] = true
		sort.Strings(b.examples)
		unit := "objects"
		if f.Resource.Namespace != "" {
			unit = "namespaces"
		}
		examples := b.examples
		truncated := len(examples) > maxRepeatExamples
		if truncated {
			examples = examples[:maxRepeatExamples]
		}
		rows = append(rows, AffectedRow{Repeat: &RepeatGroup{
			Kind:         f.Resource.Kind,
			NameTemplate: shape,
			Unit:         unit,
			Count:        b.count,
			Examples:     examples,
			Truncated:    truncated,
		}})
	}
	return rows
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
		"minus":      func(a, b int) int { return a - b },
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
		"detectedVia": func(d thirdparty.Detection) string {
			plural := func(n int) string {
				if n == 1 {
					return "object"
				}
				return "objects"
			}
			var parts []string
			if d.Group != "" && d.GroupCount > 0 {
				parts = append(parts, fmt.Sprintf("CRD group `%s` (%d %s)", d.Group, d.GroupCount, plural(d.GroupCount)))
			}
			if d.Labels != nil && d.LabelCount > 0 {
				parts = append(parts, fmt.Sprintf("label match (%d %s)", d.LabelCount, plural(d.LabelCount)))
			}
			return strings.Join(parts, ", ")
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
