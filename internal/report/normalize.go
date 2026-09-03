package report

import (
	"strings"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

// isWordByte reports whether b is a "word" byte for the same boundary
// semantics regexp's \b uses (ASCII letters/digits/underscore) — sufficient
// here since Kubernetes namespace/resource names are DNS-1123 labels
// (lowercase alphanumeric and '-' only).
func isWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// replaceWordBoundary replaces every standalone occurrence of token in s —
// bounded on both sides by a non-word byte or start/end of string, the same
// semantics as regexp `\b<token>\b` — with replacement. Deliberately not
// regexp-based: this runs once per finding on every report render (and,
// via NormalizedMessage, once per row on every triage refresh() — marking,
// filtering, sorting, search all trigger one) — a real multi-tenant
// cluster can have tens of thousands of findings, so recompiling a fresh
// *regexp.Regexp per call would be a real cost. A short, generic name
// (e.g. "sa") must still only replace itself as a standalone identifier,
// never a substring inside an unrelated word — "sa" must not turn "same"
// into a false match — which the boundary check below preserves exactly.
func replaceWordBoundary(s, token, replacement string) string {
	if token == "" {
		return s
	}
	var b strings.Builder
	rest := s
	for {
		i := strings.Index(rest, token)
		if i < 0 {
			b.WriteString(rest)
			break
		}
		before := byte(0)
		if i > 0 {
			before = rest[i-1]
		}
		afterIdx := i + len(token)
		after := byte(0)
		if afterIdx < len(rest) {
			after = rest[afterIdx]
		}
		if (i == 0 || !isWordByte(before)) && (afterIdx == len(rest) || !isWordByte(after)) {
			b.WriteString(rest[:i])
			b.WriteString(replacement)
			rest = rest[afterIdx:]
			continue
		}
		// Not a boundary match (e.g. "sa" inside "same") — keep this
		// occurrence literal and resume searching just past it, not past
		// the whole token, so a later real match starting mid-string is
		// still found.
		b.WriteString(rest[:i+1])
		rest = rest[i+1:]
	}
	return b.String()
}

// NormalizedMessage returns f.Message with any standalone occurrence of
// f's own resource namespace/name replaced by a fixed placeholder — e.g.
// "checker-sa" in namespace "pg-cl-<uuid>" reading Secrets cluster-wide via
// a per-tenant ClusterRoleBinding whose generated name also embeds that
// same namespace string. Every part of the message that isn't that
// resource's own identity (the verbs, the binding kind, which
// role/secrets are reachable) still has to match for two findings to land
// in the same MessageBucketKey bucket — this only strips the one kind of
// variance that's mechanical repetition (the same template stamped out
// once per generated tenant namespace), not substantive per-resource
// detail.
//
// This is the "same problem, different tenant" signal both the Markdown
// report (groupByCheck, via MessageBucketKey) and the triage TUI
// (internal/triage/tui/dedup.go's dedupKey) collapse repeated findings on
// — a single shared implementation so the two never again diverge the way
// they did before this function existed (the report only normalized by
// resource *name shape*; triage additionally normalized the message text
// itself, and the report's grouping had no equivalent at all).
func NormalizedMessage(f findings.Finding) string {
	msg := f.Message
	if ns := f.Resource.Namespace; ns != "" {
		msg = replaceWordBoundary(msg, ns, "\x00ns\x00")
	}
	if name := f.Resource.Name; name != "" {
		msg = replaceWordBoundary(msg, name, "\x00name\x00")
	}
	return msg
}

// MessageBucketKey is the shared "these findings are the same problem"
// grouping key: f.DedupKey if the analyzer opted into one (see
// findings.Finding's doc comment — a check whose Message legitimately
// embeds detail beyond the resource's own name, like Pod Security
// Standards naming the specific violating container, where that detail
// isn't the useful axis to bulk-group on), otherwise NormalizedMessage(f).
func MessageBucketKey(f findings.Finding) string {
	if f.DedupKey != "" {
		return "dk:" + f.DedupKey
	}
	return NormalizedMessage(f)
}
