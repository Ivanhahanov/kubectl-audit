package tui

import (
	"regexp"
	"strings"

	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

// dedupKey identifies a real "this is a repeat of the same problem"
// cluster: the same check (PolicyID) firing on the same resource Kind.
// Deliberately does NOT also require a matching resource name/shape (an
// earlier version of this did, reusing triage.GroupKey — the Markdown
// report's per-tenant-namespace collapsing key): on a real cluster, the
// common noise isn't the same literal/generated name repeated across
// tenants, it's the same check firing on many differently-named resources
// with an identical message (e.g. "workload.run-as-non-root" on 19
// different Deployments) — requiring a name match meant that almost never
// collapsed. uniformMessagePolicies is what keeps this safe: a policy only
// qualifies once every one of its findings shares the exact same message,
// so collapsing never hides resource-specific detail.
func dedupKey(r triage.Row) string {
	return r.Entry.PolicyID + "|" + r.Entry.Resource.Kind
}

// dedupKeyLabel renders a dedupKey ("PolicyID|Kind") back into a readable
// "PolicyID Kind" form for the footer's "group: ..." status while a group
// is expanded — the "|" separator is an internal map-key detail, not
// something worth showing the user.
func dedupKeyLabel(key string) string {
	return strings.ReplaceAll(key, "|", " ")
}

// identifierPattern matches a token on word boundaries so a short/generic
// resource name or namespace (e.g. "a", "sa") only ever replaces itself as a
// standalone identifier, never a substring inside an unrelated word — "sa"
// must not turn "same" into a false match. "\b" already treats "-" as a
// non-word character, so hyphenated Kubernetes names ("checker-sa",
// "pg-cl-<uuid>") get correct boundaries at each hyphen too.
func identifierPattern(token string) *regexp.Regexp {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(token) + `\b`)
}

// normalizedMessage returns r.Finding.Message with any standalone occurrence
// of this finding's OWN resource namespace/name replaced by a fixed
// placeholder — e.g. "checker-sa" in namespace "pg-cl-<uuid>" reading
// Secrets cluster-wide via a per-tenant ClusterRoleBinding whose generated
// name also embeds that same namespace string. Every part of the message
// that isn't that resource's own identity (the verbs, the binding kind,
// which role/secrets are reachable) still has to match for
// uniformMessagePolicies to treat the policy as collapsible — this only
// strips the one kind of variance that's mechanical repetition (the same
// template stamped out once per generated tenant namespace), not
// substantive per-resource detail.
func normalizedMessage(r triage.Row) string {
	msg := r.Finding.Message
	if ns := r.Entry.Resource.Namespace; ns != "" {
		msg = identifierPattern(ns).ReplaceAllString(msg, "\x00ns\x00")
	}
	if name := r.Entry.Resource.Name; name != "" {
		msg = identifierPattern(name).ReplaceAllString(msg, "\x00name\x00")
	}
	return msg
}

// uniformMessagePolicies reports, for each PolicyID present in rows,
// whether every one of that policy's live (non-resolved) findings has an
// identical normalizedMessage. Mirrors internal/report/template.go's
// groupByCheck "uniform" computation, extended with normalizedMessage: a
// message that's the same for every finding a check produces (once each
// finding's own resource name/namespace is normalized out) proves the
// message has no *substantive* per-resource detail baked in — true of
// essentially every VAP/CEL check outright, and also true of a native
// analyzer finding that's really the same templated grant reissued once per
// generated tenant namespace. A policy whose message embeds real
// per-resource detail beyond its own identity (different verbs, different
// reachable secrets, a different binding shape) still never collapses —
// that detail survives normalization and keeps the messages apart.
func uniformMessagePolicies(rows []triage.Row) map[string]bool {
	message := map[string]string{}
	uniform := map[string]bool{}
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Finding == nil {
			continue
		}
		id := r.Entry.PolicyID
		msg := normalizedMessage(r)
		if !seen[id] {
			seen[id] = true
			message[id] = msg
			uniform[id] = true
			continue
		}
		if uniform[id] && message[id] != msg {
			uniform[id] = false
		}
	}
	return uniform
}

// dedupGroups collapses rows into one representative row per dedupKey
// bucket once that bucket has at least threshold members (and its policy
// passes uniformMessagePolicies) — the actual noise reduction: instead of
// scrolling past the same check repeated once per tenant namespace, the
// triager sees it once, with a count. threshold <= 0 disables collapsing
// entirely (mirrors groupAffectedResources's convention in
// internal/report), returning every row unchanged. Resolved rows (no live
// Finding) never collapse — there's nothing left to bulk-act on. members
// maps a representative row's FindingID to its full bucket (including
// itself) — the shape callers need for bulk actions and the detail view.
func dedupGroups(rows []triage.Row, threshold int) (result []triage.Row, members map[string][]triage.Row) {
	members = map[string][]triage.Row{}
	if threshold <= 0 {
		return rows, members
	}

	uniform := uniformMessagePolicies(rows)
	eligible := func(r triage.Row) bool {
		return r.Finding != nil && uniform[r.Entry.PolicyID]
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
