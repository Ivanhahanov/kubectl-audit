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
	// Description is the organization's own explanation of the
	// vulnerability — distinct from Finding.Message (the tool's own,
	// sometimes per-resource, technical text), which is never replaced,
	// only shown alongside a Description override as "Technical detail"
	// (see internal/triage.ResolvedContent).
	Description string `json:"description,omitempty"`
	Remediation string `json:"remediation,omitempty"`
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
func NewID(policyID string, ref ResourceRef, extra ...string) string {
	parts := []string{policyID, ref.APIVersion, ref.Kind, ref.Namespace, ref.Name}
	parts = append(parts, extra...)
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])[:16]
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
