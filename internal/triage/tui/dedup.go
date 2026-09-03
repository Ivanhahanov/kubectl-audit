package tui

import (
	"strings"

	"github.com/ivanhahanov/kubectl-audit/internal/report"
	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

// dedupKey identifies a real "this is a repeat of the same problem"
// cluster: the same check (PolicyID) firing on the same resource Kind with
// the same report.MessageBucketKey (see below). Deliberately does NOT also
// require a matching resource name/shape (an earlier version of this did,
// reusing triage.GroupKey — the Markdown report's per-tenant-namespace
// collapsing key): on a real cluster, the common noise isn't the same
// literal/generated name repeated across tenants, it's the same check
// firing on many differently-named resources with an identical message
// (e.g. "workload.run-as-non-root" on 19 different Deployments) —
// requiring a name match meant that almost never collapsed.
//
// Bucketing directly on the message (rather than a separate policy-wide
// "are all of this policy's messages uniform" gate, which an
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
//
// r.Finding.DedupKey, when an analyzer sets it (see findings.Finding's doc
// comment), overrides the message-based bucketing dimension entirely — for
// checks whose Message legitimately embeds real per-resource detail that
// isn't the useful axis to bulk-triage on (e.g. Pod Security Standards
// naming the specific violating container), letting the analyzer opt into
// a coarser grouping without the TUI having to guess which part of an
// arbitrary Message is "identity" versus "the actual signal". See
// report.MessageBucketKey, the shared implementation the Markdown report's
// own grouping (internal/report/template.go's groupByCheck) now uses too.
// Callers must only call dedupKey with r.Finding != nil (the same contract
// report.MessageBucketKey already assumes).
func dedupKey(r triage.Row) string {
	return r.Entry.PolicyID + "|" + r.Entry.Resource.Kind + "|" + report.MessageBucketKey(*r.Finding)
}

// dedupKeyLabel renders a dedupKey back into a readable "PolicyID Kind" form
// for the footer's "group: ..." status while a group is expanded — the
// message-bucket segment is dropped (it's the internal bucketing detail,
// not something worth printing, and can be long).
func dedupKeyLabel(key string) string {
	parts := strings.SplitN(key, "|", 3)
	if len(parts) < 2 {
		return strings.ReplaceAll(key, "|", " ")
	}
	return parts[0] + " " + parts[1]
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
// bundles PolicyID+Kind+report.MessageBucketKey, so a policy whose findings
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
