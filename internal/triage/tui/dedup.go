package tui

import (
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

// uniformMessagePolicies reports, for each PolicyID present in rows,
// whether every one of that policy's live (non-resolved) findings has an
// identical Message. Mirrors internal/report/template.go's groupByCheck
// "uniform" computation exactly: a message that's the same for every
// finding a check produces proves the message has no per-resource detail
// baked in (true of essentially every VAP/CEL check), so collapsing is
// lossless. A policy whose message embeds resource-specific detail (native
// analyzers like RBAC/PSS, which describe exactly what's wrong per
// resource) must never collapse — doing so would silently hide that detail.
func uniformMessagePolicies(rows []triage.Row) map[string]bool {
	message := map[string]string{}
	uniform := map[string]bool{}
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Finding == nil {
			continue
		}
		id := r.Entry.PolicyID
		if !seen[id] {
			seen[id] = true
			message[id] = r.Finding.Message
			uniform[id] = true
			continue
		}
		if uniform[id] && message[id] != r.Finding.Message {
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
