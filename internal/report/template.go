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

//go:embed templates/confluence.tpl
var confluenceTemplateSource string

//go:embed templates/ru.md.tpl
var russianTemplateSource string

// DefaultTemplate returns the built-in report.md.tpl source, e.g. for
// `kubectl-audit template dump` to give users a starting point to
// customize.
func DefaultTemplate() string {
	return defaultTemplateSource
}

// DefaultConfluenceTemplate returns the built-in confluence.tpl source
// (Confluence Server/Data Center wiki markup), e.g. for `kubectl-audit
// template dump --format confluence` to give users a starting point to
// customize.
func DefaultConfluenceTemplate() string {
	return confluenceTemplateSource
}

// RussianTemplate returns the built-in ru.md.tpl source — the same report
// structure as the default (English) Markdown template, with Russian
// section labels, e.g. for `kubectl-audit template dump --format ru` to
// give users a starting point to customize. Selected via --report-lang ru
// (config output.reportLang) when --report-template isn't set.
func RussianTemplate() string {
	return russianTemplateSource
}

// severityRU translates a Severity's built-in English constant
// ("CRITICAL", ...) into its Russian equivalent, for ru.md.tpl. Falls back
// to the raw value for anything unrecognized (defensive only — the 5
// findings.Severity constants are exhaustive today).
func severityRU(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical:
		return "Критический"
	case findings.SeverityHigh:
		return "Высокий"
	case findings.SeverityMedium:
		return "Средний"
	case findings.SeverityLow:
		return "Низкий"
	case findings.SeverityInfo:
		return "Информационный"
	default:
		return string(s)
	}
}

// unitRU translates a RepeatGroup.Unit ("namespaces" or "objects", the
// only two values groupAffectedResources ever produces) for ru.md.tpl.
// Falls back to the raw value for anything unrecognized.
func unitRU(unit string) string {
	switch unit {
	case "namespaces":
		return "пространствах имён"
	case "objects":
		return "объектах"
	default:
		return unit
	}
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
// and remediation text for each one.
//
// MessageGroups replaces an earlier single UniformMessage/Rows pair that
// gated on the WHOLE policy's messages being identical — one outlier
// finding anywhere under the same PolicyID (a real-cluster case: a native
// analyzer message that's mostly identical across tenants but differs for
// one unrelated subject) used to block collapsing for every other,
// genuinely-identical, finding under that same check too, falling all the
// way back to listing every single finding individually. See
// MessageBucketKey.
type CheckGroup struct {
	PolicyID    string
	Title       string
	Category    string
	CIS         []string
	Remediation string
	// Findings is every finding under this PolicyID, flat — used for the
	// "Affected resources (N)" total count. See MessageGroups for how
	// they're actually rendered.
	Findings []findings.Finding
	// MessageGroups buckets Findings by MessageBucketKey — findings under
	// this policy that share an (post-normalization) identical message, or
	// the same analyzer-provided DedupKey. Each bucket's affected
	// resources are further collapsed by Kind/name-shape within
	// themselves (see groupAffectedResources) once the bucket's own size
	// reaches namespaceGroupThreshold — a check whose messages
	// legitimately differ per resource (RBAC/PSS/control-plane) naturally
	// produces multiple small buckets instead of one gated all-or-nothing
	// decision for the whole policy.
	MessageGroups []MessageGroup
	// Collapsible is true when this check has more than
	// checkCollapseThreshold findings — the template wraps its Affected
	// resources section in a <details>/{expand} block so a check that
	// fires on many resources doesn't push everything below it off screen
	// by default. Independent of namespaceGroupThreshold (which controls
	// RepeatGroup collapsing within a bucket): a check with, say, 40
	// distinct per-resource messages that never collapse into a
	// RepeatGroup still benefits from being tucked behind a click.
	Collapsible bool
}

// checkCollapseThreshold is the finding-count above which a CheckGroup's
// Affected resources section renders collapsed by default (see
// CheckGroup.Collapsible). Deliberately not tied to namespaceGroupThreshold
// — that threshold is about whether individual rows collapse into one
// RepeatGroup, a different question from how many rows are comfortable to
// show open by default regardless of whether they collapsed.
const checkCollapseThreshold = 8

// MessageGroup is every finding under one CheckGroup sharing an identical
// MessageBucketKey — the report's "same problem, shown once" unit. Message
// is one representative finding's own literal text (not the normalized/
// placeholder form MessageBucketKey uses only for bucketing).
type MessageGroup struct {
	Message string
	// Rows is how the template renders this bucket's "Affected resources":
	// findings.Finding rows verbatim, except a group sharing the same Kind
	// and "name shape" (see NameTemplate) — at least
	// namespaceGroupThreshold of them — collapses into one AffectedRow
	// instead of one row each. See AffectedRow and groupAffectedResources.
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
// (see NameTemplate). Unit is "namespaces" when every collapsed finding is a
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
// thousands of matching namespaces (see the docstring on NameTemplate), and
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

// NameTemplate normalizes a resource name to a "shape" for grouping: runs
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
//
// Exported for internal/triage, which reuses the exact same clustering
// signal for its "apply this triage decision to every matching finding"
// bulk action — the two features share one heuristic rather than each
// maintaining their own copy.
func NameTemplate(name string) string {
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
			groups[i].Checks = groupByCheck(groups[i].Findings, r.NamespaceGroupThreshold, r.GroupByNamePattern, r.KnowledgeBase)
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
// preserving first-seen order, then buckets each policy's findings again by
// MessageBucketKey into MessageGroups (see CheckGroup's doc comment for
// why: no whole-policy "are all messages uniform" gate — one outlier
// finding must never block collapsing for the rest of the check).
// namespaceGroupThreshold and byPattern are forwarded to
// groupAffectedResources for each MessageGroup's own Rows; threshold <= 0
// disables the *resource*-level RepeatGroup collapsing (groupAffectedResources
// then returns one row per finding), but message-level grouping — sharing
// one message line instead of repeating it per resource — still applies
// regardless, same as it always has. kb applies an organization's own
// Title/Category/Remediation overrides (see resolveCheckKB); nil means no
// overrides, today's behavior.
func groupByCheck(sorted []findings.Finding, namespaceGroupThreshold int, byPattern bool, kb map[string]findings.KnowledgeBaseEntry) []CheckGroup {
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
		title, category, remediation := resolveCheckKB(fs[0], kb)
		out = append(out, CheckGroup{
			PolicyID:      id,
			Title:         title,
			Category:      category,
			CIS:           fs[0].CIS,
			Remediation:   remediation,
			Findings:      fs,
			MessageGroups: groupByMessage(fs, namespaceGroupThreshold, byPattern),
			Collapsible:   len(fs) > checkCollapseThreshold,
		})
	}
	return out
}

// resolveCheckKB applies an organization's own knowledge-base override to
// one check's hoisted Title/Category/Remediation — the same precedence
// triage.Resolve uses (internal/triage/knowledgebase.go): f.KnowledgeBase
// (inline, set via a VAP's kb-* annotations) first, then kb[f.PolicyID] (an
// external triage.knowledgeBaseFile) layered on top, external always wins
// field-by-field. Each field is rendered as a Go template against
// {{.Finding}} (f — the same representative finding already hoisted for
// Title/CIS/Remediation elsewhere in groupByCheck), same as
// triage.Resolve/renderKBField: the bundled starter-ru.yaml knowledge base
// (and any real-world custom one) writes Remediation as a template — e.g.
// "...roles bound to {{.Finding.Resource.Kind}} {{.Finding.Resource.Name}}"
// — so skipping rendering here would leak literal "{{...}}" syntax into
// the report. A template parse/exec error leaves that field at whatever it
// already was (the tool's default, or an earlier layer's value) rather
// than showing broken syntax or failing the whole report — same
// graceful-degradation behavior as triage.Resolve. No "(org)"/"(knowledge
// base)" suffix is added anywhere — overridden content blends in under the
// same plain labels as default content, matching the triage TUI's existing
// detail view.
func resolveCheckKB(f findings.Finding, kb map[string]findings.KnowledgeBaseEntry) (title, category, remediation string) {
	title, category, remediation = f.Title, f.Category, f.Remediation
	apply := func(e findings.KnowledgeBaseEntry) {
		if e.Title != "" {
			if rendered, err := renderKBField("kb-title", e.Title, f); err == nil {
				title = rendered
			}
		}
		if e.Category != "" {
			if rendered, err := renderKBField("kb-category", e.Category, f); err == nil {
				category = rendered
			}
		}
		if e.Remediation != "" {
			if rendered, err := renderKBField("kb-remediation", e.Remediation, f); err == nil {
				remediation = rendered
			}
		}
	}
	if f.KnowledgeBase != nil {
		apply(*f.KnowledgeBase)
	}
	if e, ok := kb[f.PolicyID]; ok {
		apply(e)
	}
	return title, category, remediation
}

// renderKBField parses and executes tplSource as a Go template against
// {{.Finding}} — mirrors internal/triage/knowledgebase.go's renderKBField
// (kept as a separate copy, not shared: report can't import triage, since
// triage already imports report for NormalizedMessage/MessageBucketKey,
// and the reverse would cycle).
func renderKBField(name, tplSource string, f findings.Finding) (string, error) {
	tpl, err := template.New(name).Funcs(templateFuncs()).Parse(tplSource)
	if err != nil {
		return "", fmt.Errorf("parsing %s: %w", name, err)
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, struct{ Finding findings.Finding }{f}); err != nil {
		return "", fmt.Errorf("executing %s: %w", name, err)
	}
	return buf.String(), nil
}

// groupByMessage buckets one check's findings by MessageBucketKey,
// preserving first-seen order, and builds each bucket's Rows via the
// existing, unmodified groupAffectedResources (the Kind/name-shape
// collapsing within a bucket is unchanged — only the outer bucketing that
// used to gate on whole-policy uniformity is new).
func groupByMessage(fs []findings.Finding, namespaceGroupThreshold int, byPattern bool) []MessageGroup {
	var order []string
	buckets := map[string][]findings.Finding{}
	for _, f := range fs {
		k := MessageBucketKey(f)
		if _, ok := buckets[k]; !ok {
			order = append(order, k)
		}
		buckets[k] = append(buckets[k], f)
	}

	out := make([]MessageGroup, 0, len(order))
	for _, k := range order {
		bucket := buckets[k]
		out = append(out, MessageGroup{
			Message: bucket[0].Message,
			Rows:    groupAffectedResources(bucket, namespaceGroupThreshold, byPattern),
		})
	}
	return out
}

// groupAffectedResources collapses a check's findings into AffectedRows: a
// group of at least threshold findings sharing a Kind and name shape
// collapses into one RepeatGroup row; everything else stays one row per
// finding. The name shape is either the exact Name (byPattern false — the
// same Deployment name "app" repeated across several tenant namespaces is
// the canonical case) or NameTemplate(Name) (byPattern true — additionally
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
			shape = NameTemplate(f.Resource.Name)
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
			shape = NameTemplate(f.Resource.Name)
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
		"severityRU": severityRU,
		"unitRU":     unitRU,
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

// RenderConfluence renders the report as Confluence Server/Data Center
// wiki markup instead of Markdown — same TemplateData, a different .tpl
// and funcMap (see confluenceTemplateFuncs). An empty tplSource uses the
// embedded default template; a non-empty one (e.g. loaded from
// --confluence-template) fully replaces it.
func RenderConfluence(r Result, tplSource string) (string, error) {
	if tplSource == "" {
		tplSource = confluenceTemplateSource
	}
	tpl, err := template.New("confluence").Funcs(confluenceTemplateFuncs()).Parse(tplSource)
	if err != nil {
		return "", fmt.Errorf("parsing confluence template: %w", err)
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, newTemplateData(r)); err != nil {
		return "", fmt.Errorf("executing confluence template: %w", err)
	}
	return buf.String(), nil
}

// confluenceTemplateFuncs is templateFuncs() adapted for Confluence wiki
// markup: reuses every format-agnostic helper as-is (escapeCell/orDash/
// join/minus/rfc3339/bindingLabels/crossRefs/detectedVia/failingControls/
// statusNotes all return plain or already-escaped strings, no Markdown
// syntax baked in), drops slug (Confluence's own {toc} macro builds
// anchors/navigation natively — no hand-built anchor scheme needed), and
// adds severityStatus for the one Confluence-only enhancement with no
// Markdown equivalent: a {status:...} colour lozenge next to each check
// heading.
func confluenceTemplateFuncs() template.FuncMap {
	fns := templateFuncs()
	delete(fns, "slug")
	fns["severityStatus"] = severityStatus
	return fns
}

// severityStatus renders a Confluence {status} macro for a severity —
// colour-coded so a check's risk level is visible at a glance without
// reading the heading text.
func severityStatus(s findings.Severity) string {
	colour := "Grey"
	switch s {
	case findings.SeverityCritical, findings.SeverityHigh:
		colour = "Red"
	case findings.SeverityMedium:
		colour = "Yellow"
	case findings.SeverityLow:
		colour = "Blue"
	}
	return fmt.Sprintf("{status:colour=%s|title=%s}", colour, s)
}
