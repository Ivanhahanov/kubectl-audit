package tui

import (
	"strings"

	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

// dedupKey identifies a real "this is a repeat of the same problem"
// cluster: the same check (PolicyID) firing on the same resource Kind with
// the same normalizedMessage (see below). Deliberately does NOT also
// require a matching resource name/shape (an earlier version of this did,
// reusing triage.GroupKey — the Markdown report's per-tenant-namespace
// collapsing key): on a real cluster, the common noise isn't the same
// literal/generated name repeated across tenants, it's the same check
// firing on many differently-named resources with an identical message
// (e.g. "workload.run-as-non-root" on 19 different Deployments) —
// requiring a name match meant that almost never collapsed.
//
// Bucketing directly on normalizedMessage (rather than a separate
// policy-wide "are all of this policy's messages uniform" gate, which an
// earlier version of this file used) is what makes collapsing safe AND
// robust to real-world variance: two findings under the same policy whose
// messages differ in substance (different verbs, a different binding
// shape, a Group subject instead of a ServiceAccount) simply land in
// different buckets and never collapse together — without a global gate
// where a single such outlier anywhere in the policy's findings used to
// block every other, genuinely-identical, bucket in that same policy from
// collapsing at all (the real-cluster bug this replaced: thousands of
// identical per-tenant rbac-analyzer.broad-secrets-access findings never
// collapsed because one unrelated finding under the same PolicyID had a
// differently-shaped message).
func dedupKey(r triage.Row) string {
	return r.Entry.PolicyID + "|" + r.Entry.Resource.Kind + "|" + normalizedMessage(r)
}

// dedupKeyLabel renders a dedupKey back into a readable "PolicyID Kind" form
// for the footer's "group: ..." status while a group is expanded — the
// normalizedMessage segment is dropped (it's the internal bucketing detail,
// not something worth printing, and can be long).
func dedupKeyLabel(key string) string {
	parts := strings.SplitN(key, "|", 3)
	if len(parts) < 2 {
		return strings.ReplaceAll(key, "|", " ")
	}
	return parts[0] + " " + parts[1]
}

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
// regexp-based: dedupKey (and so this function) runs once per row on every
// refresh() — marking, filtering, sorting, search all trigger one — and a
// real multi-tenant cluster can have thousands of findings, so recompiling
// a fresh *regexp.Regexp for every row on every keystroke would be a real
// cost. A short, generic name (e.g. "sa") must still only replace itself as
// a standalone identifier, never a substring inside an unrelated word — "sa"
// must not turn "same" into a false match — which the boundary check below
// preserves exactly.
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

// normalizedMessage returns r.Finding.Message with any standalone occurrence
// of this finding's OWN resource namespace/name replaced by a fixed
// placeholder — e.g. "checker-sa" in namespace "pg-cl-<uuid>" reading
// Secrets cluster-wide via a per-tenant ClusterRoleBinding whose generated
// name also embeds that same namespace string. Every part of the message
// that isn't that resource's own identity (the verbs, the binding kind,
// which role/secrets are reachable) still has to match for two findings to
// land in the same dedupKey bucket — this only strips the one kind of
// variance that's mechanical repetition (the same template stamped out
// once per generated tenant namespace), not substantive per-resource
// detail.
func normalizedMessage(r triage.Row) string {
	msg := r.Finding.Message
	if ns := r.Entry.Resource.Namespace; ns != "" {
		msg = replaceWordBoundary(msg, ns, "\x00ns\x00")
	}
	if name := r.Entry.Resource.Name; name != "" {
		msg = replaceWordBoundary(msg, name, "\x00name\x00")
	}
	return msg
}

// dedupGroups collapses rows into one representative row per dedupKey
// bucket once that bucket has at least threshold members — the actual
// noise reduction: instead of scrolling past the same check repeated once
// per tenant namespace, the triager sees it once, with a count. threshold
// <= 0 disables collapsing entirely (mirrors groupAffectedResources's
// convention in internal/report), returning every row unchanged. Resolved
// rows (no live Finding) never collapse — there's nothing left to bulk-act
// on. members maps a representative row's FindingID to its full bucket
// (including itself) — the shape callers need for bulk actions and the
// detail view.
//
// No separate "is this policy safe to collapse" gate: dedupKey already
// bundles PolicyID+Kind+normalizedMessage, so a policy whose findings
// genuinely differ (real per-resource detail beyond the resource's own
// name/namespace) naturally produces multiple buckets, each too small to
// collapse on its own unless there really are >= threshold identical ones
// — no risk of hiding resource-specific detail, and no risk of one
// unrelated outlier finding blocking every other bucket under the same
// policy from collapsing.
func dedupGroups(rows []triage.Row, threshold int) (result []triage.Row, members map[string][]triage.Row) {
	members = map[string][]triage.Row{}
	if threshold <= 0 {
		return rows, members
	}

	eligible := func(r triage.Row) bool {
		return r.Finding != nil
	}

	buckets := map[string][]triage.Row{}
	var order []string
	for _, r := range rows {
		if !eligible(r) {
			continue
		}
		k := dedupKey(r)
		if _, ok := buckets[k]; !ok {
			order = append(order, k)
		}
		buckets[k] = append(buckets[k], r)
	}

	collapse := map[string]bool{}
	for _, k := range order {
		if len(buckets[k]) >= threshold {
			collapse[k] = true
		}
	}

	result = make([]triage.Row, 0, len(rows))
	emitted := map[string]bool{}
	for _, r := range rows {
		if !eligible(r) {
			result = append(result, r)
			continue
		}
		k := dedupKey(r)
		if !collapse[k] {
			result = append(result, r)
			continue
		}
		if emitted[k] {
			continue
		}
		emitted[k] = true
		rep := buckets[k][0]
		members[rep.Entry.FindingID] = buckets[k]
		result = append(result, rep)
	}
	return result, members
}
