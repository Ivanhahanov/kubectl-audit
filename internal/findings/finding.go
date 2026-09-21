// Package findings defines the unified finding model produced by the policy
// engine, the RBAC analyzer and the CIS scorecard builder.
package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Severity is the risk level of a Finding, ordered from least to most severe.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// severityRank gives a total order to severities so results can be sorted
// and compared against a --fail-on threshold.
var severityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// ParseSeverity normalizes free-form severity strings (case-insensitive) to a
// known Severity, defaulting to SeverityMedium for unrecognized values.
func ParseSeverity(s string) Severity {
	switch normalize(s) {
	case "info", "informational":
		return SeverityInfo
	case "low":
		return SeverityLow
	case "medium", "moderate":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityMedium
	}
}

func normalize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}

// AtLeast reports whether the severity meets or exceeds the threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	return severityRank[s] >= severityRank[threshold]
}

// Rank returns the numeric rank of the severity (higher = more severe).
func (s Severity) Rank() int {
	return severityRank[s]
}

// ResourceRef identifies the Kubernetes object (or subject, for RBAC
// findings) a Finding is about.
type ResourceRef struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

func (r ResourceRef) String() string {
	if r.Namespace != "" {
		return fmt.Sprintf("%s/%s %s/%s", r.APIVersion, r.Kind, r.Namespace, r.Name)
	}
	return fmt.Sprintf("%s/%s %s", r.APIVersion, r.Kind, r.Name)
}

// Finding is a single audit result: a policy or analyzer flagged a resource.
type Finding struct {
	ID          string      `json:"id"`
	PolicyID    string      `json:"policyId"`
	Title       string      `json:"title"`
	Severity    Severity    `json:"severity"`
	Category    string      `json:"category"`
	CIS         []string    `json:"cis,omitempty"`
	Resource    ResourceRef `json:"resource"`
	Message     string      `json:"message"`
	Remediation string      `json:"remediation,omitempty"`
	// VerificationSteps tells a human triaging this finding how to confirm
	// it's a true positive in their specific environment before acting on
	// it (e.g. "check whether this Service is actually internet-reachable"
	// rather than assuming the worst from the static manifest alone) — see
	// docs/triage.md. Distinct from Remediation, which says how to fix a
	// confirmed issue, not how to confirm it in the first place.
	VerificationSteps string `json:"verificationSteps,omitempty"`
	Source            string `json:"source,omitempty"`
	// KnowledgeBase is an organization's own ticket-facing content for this
	// finding's check — Title/Description/Remediation written to match
	// internal standards, house style, or just a clearer explanation than
	// the tool's own default — populated for a VAP policy that sets
	// kb-title/kb-description/kb-remediation annotations directly (see
	// docs/writing-policies.md), so a custom policy's author writes the
	// check and its ticket wording in one file. Nil if the policy sets
	// none. This is deliberately not about language/translation: Message
	// (the tool's own, sometimes per-resource, technical text) is never
	// overridden here — see internal/triage.Resolve, which layers this
	// on top of a separate external knowledge-base file and decides what
	// a Jira ticket (and the triage TUI's detail view) actually shows.
	KnowledgeBase *KnowledgeBaseEntry `json:"knowledgeBase,omitempty"`
	// DedupKey is an optional grouping hint for the triage TUI's bulk-noise
	// collapsing (see internal/triage/tui/dedup.go): when set, findings that
	// share PolicyID+Resource.Kind+DedupKey collapse together in the
	// "roll up" view, instead of the default (PolicyID+Kind+Message).
	//
	// Only needed when Message legitimately embeds real per-resource detail
	// (beyond the resource's own name/namespace, which the TUI already
	// strips) that isn't the useful axis to bulk-triage on — e.g. Pod
	// Security Standards' ForbiddenDetail names the specific container
	// ("runAsNonRoot != true (container api-v2)"), so on a cluster with
	// thousands of unrelated tenant workloads each independently missing
	// the same securityContext field, the container name alone was enough
	// to keep every one of them a separate row even though they're all the
	// same actionable category of gap this tool can't fix on the tenant's
	// behalf anyway. DedupKey lets an analyzer opt a check into a coarser
	// grouping (e.g. just the violated rule names, no per-container/port/
	// capability detail) for the collapsed view only — it never affects
	// Message, Remediation, or a filed Jira ticket, and the full per-finding
	// detail is still one keypress ('g') away.
	DedupKey string `json:"dedupKey,omitempty"`
}

// KnowledgeBaseEntry is an organization's own ticket-facing content for one
// check, overriding the tool's default Title/Description/Remediation. A
// field left empty here leaves that piece of content at its default — see
// internal/triage.Resolve.
type KnowledgeBaseEntry struct {
	Title string `json:"title,omitempty"`
	// Category overrides Finding.Category for display purposes only (the
	// Markdown/Confluence report heading, the CSV column, Jira's auto
	// "category" label) — a free-text label with no structural role
	// elsewhere (compliance scoring keys on PolicyID, not Category), so
	// overriding it here is safe.
	Category string `json:"category,omitempty"`
	// Description is the organization's own explanation of the
	// vulnerability — distinct from Finding.Message (the tool's own,
	// sometimes per-resource, technical text), which is never replaced,
	// only shown alongside a Description override as "Technical detail"
	// (see internal/triage.ResolvedContent).
	Description string `json:"description,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	// VerificationSteps overrides Finding.VerificationSteps — the check's own
	// generic "how to confirm this isn't a false positive" instructions.
	// Meant for organization-specific process detail a check can't know
	// (which team owns a naming convention, an internal escalation channel,
	// a link to an internal wiki page) layered on top of or replacing the
	// tool's own steps — not for re-deriving what the check already knows
	// about the resource itself.
	VerificationSteps string `json:"verificationSteps,omitempty"`
	// Labels are extra Jira labels for this specific check — org-defined,
	// the same for every finding this policy produces, e.g. an internal
	// compliance requirement id ("k-ose-5"). Merged into the auto-derived
	// + triage.jira.extraLabels set (see triage.IssueLabels); each entry is
	// sanitized the same way. Not Go-templated (unlike
	// Title/Description/Remediation) — a Jira label is a short fixed slug,
	// not free text worth per-resource substitution.
	Labels []string `json:"labels,omitempty"`
}

// NewID computes a stable, content-addressed finding ID from the policy,
// resource identity, and any extra discriminators (e.g. the specific
// validation expression or verb that triggered), so distinct violations of
// the same policy against the same resource don't collide into one ID and
// silently disappear during Dedupe.
//
// Deliberately does NOT include which cluster/target produced the finding
// — every analyzer calls NewID independently (see internal/rbac,
// internal/pss, internal/engine, ...) with no cluster context available at
// that point, and baking cluster identity in here would mean threading it
// through every one of those call sites for no benefit within a single
// scan (Dedupe only ever compares findings from the same scan). Multi-scan/
// multi-cluster identity is applied once, after all findings are combined
// — see ScopeFindingIDs.
func NewID(policyID string, ref ResourceRef, extra ...string) string {
	parts := []string{policyID, ref.APIVersion, ref.Kind, ref.Namespace, ref.Name}
	parts = append(parts, extra...)
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])[:16]
}

// ScopeID re-derives a finding ID to also depend on scope (in practice,
// the scan's own Target label — "cluster:<name>" or "static:<paths>") —
// NewID alone only depends on PolicyID+Resource identity, which two
// different clusters running the same GitOps-templated manifest (a common
// shape: identical namespace/Deployment names stamped out from one
// template) can trivially produce the same ID for. That's invisible
// within a single scan (nothing else to collide with), but becomes a real
// bug the moment two clusters' findings/triage state share one namespace
// — e.g. a central Postgres store keying triage_entries by finding ID —
// where an unrelated finding from cluster B could silently inherit
// cluster A's triage status. ScopeID is a pure function of (id, scope) so
// it's called once, after combining every analyzer's findings for one
// scan, rather than threaded through every NewID call site.
func ScopeID(id, scope string) string {
	h := sha256.Sum256([]byte(scope + "|" + id))
	return hex.EncodeToString(h[:])[:16]
}

// ScopeFindingIDs rewrites every finding's ID in place via ScopeID(f.ID,
// scope) — the one call site each scan-producing command (scan, rbac
// analyze) needs, right after combining all analyzers' findings and before
// Dedupe (Dedupe's behavior is unaffected either way: ScopeID is
// deterministic, so two findings sharing an ID before scoping still share
// one after).
func ScopeFindingIDs(in []Finding, scope string) {
	for i := range in {
		in[i].ID = ScopeID(in[i].ID, scope)
	}
}

// Dedupe removes findings with identical IDs, keeping the first occurrence.
func Dedupe(in []Finding) []Finding {
	seen := make(map[string]bool, len(in))
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		out = append(out, f)
	}
	return out
}

// SortBySeverity orders findings most-severe first, then by resource
// namespace/name for stable, readable output.
func SortBySeverity(in []Finding) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Severity.Rank() != in[j].Severity.Rank() {
			return in[i].Severity.Rank() > in[j].Severity.Rank()
		}
		if in[i].Resource.Namespace != in[j].Resource.Namespace {
			return in[i].Resource.Namespace < in[j].Resource.Namespace
		}
		if in[i].Resource.Name != in[j].Resource.Name {
			return in[i].Resource.Name < in[j].Resource.Name
		}
		return in[i].PolicyID < in[j].PolicyID
	})
}

// Summary counts findings per severity.
type Summary map[Severity]int

// Summarize builds a Summary from a finding list.
func Summarize(in []Finding) Summary {
	s := Summary{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}
	for _, f := range in {
		s[f.Severity]++
	}
	return s
}

// MaxSeverity returns the highest severity present, or "" if in is empty.
func MaxSeverity(in []Finding) Severity {
	var max Severity
	best := -1
	for _, f := range in {
		if r := f.Severity.Rank(); r > best {
			best = r
			max = f.Severity
		}
	}
	return max
}
