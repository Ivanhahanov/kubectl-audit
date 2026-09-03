package report

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

func normFinding(ns, name, msg string) findings.Finding {
	return findings.Finding{
		Resource: findings.ResourceRef{Kind: "Deployment", Namespace: ns, Name: name},
		Message:  msg,
	}
}

// TestNormalizedMessage_StripsOwnNamespaceAndName is the "same problem,
// different tenant" signal — a finding's own namespace/name embedded in
// its Message shouldn't block two otherwise-identical findings on
// different tenants from being recognized as the same problem.
func TestNormalizedMessage_StripsOwnNamespaceAndName(t *testing.T) {
	a := normFinding("pg-cl-aaa", "checker-sa", `ServiceAccount "checker-sa" in namespace "pg-cl-aaa" can read Secrets cluster-wide.`)
	b := normFinding("pg-cl-bbb", "checker-sa", `ServiceAccount "checker-sa" in namespace "pg-cl-bbb" can read Secrets cluster-wide.`)

	if got := NormalizedMessage(a); got != NormalizedMessage(b) {
		t.Errorf("expected both tenants' normalized messages to match, got %q vs %q", NormalizedMessage(a), NormalizedMessage(b))
	}
}

// TestNormalizedMessage_WordBoundarySafe guards against a short/generic
// name (e.g. "sa") matching as a substring inside an unrelated word (e.g.
// "same") — the exact regression this word-boundary-aware implementation
// exists to prevent.
func TestNormalizedMessage_WordBoundarySafe(t *testing.T) {
	f := normFinding("ns", "sa", "the same resource is unaffected")
	got := NormalizedMessage(f)
	if got != "the same resource is unaffected" {
		t.Errorf("expected \"sa\" to not match inside \"same\", got %q", got)
	}
}

// TestNormalizedMessage_SubstantiveDifferenceSurvives guards against
// over-normalizing: two findings whose messages differ in substance (not
// just the resource's own name/namespace) must still normalize
// differently.
func TestNormalizedMessage_SubstantiveDifferenceSurvives(t *testing.T) {
	a := normFinding("ns-a", "sa", `ServiceAccount "sa" can read Secrets across 2 namespaces.`)
	b := normFinding("ns-b", "sa", `ServiceAccount "sa" can read Secrets cluster-wide.`)
	if NormalizedMessage(a) == NormalizedMessage(b) {
		t.Errorf("expected substantively different messages to stay distinct, both normalized to %q", NormalizedMessage(a))
	}
}

// TestMessageBucketKey_DedupKeyOverridesMessage is the opt-in coarser
// grouping an analyzer can request (see findings.Finding.DedupKey) —
// e.g. Pod Security Standards naming the specific violating container,
// where the container name shouldn't block bulk-grouping by which rule
// was violated.
func TestMessageBucketKey_DedupKeyOverridesMessage(t *testing.T) {
	a := normFinding("ns", "app-a", "runAsNonRoot != true (container app-a)")
	a.DedupKey = "pss-analyzer.restricted|runAsNonRoot != true"
	b := normFinding("ns", "app-b", "runAsNonRoot != true (container app-b)")
	b.DedupKey = "pss-analyzer.restricted|runAsNonRoot != true"

	if MessageBucketKey(a) != MessageBucketKey(b) {
		t.Errorf("expected matching DedupKey to override differing messages, got %q vs %q", MessageBucketKey(a), MessageBucketKey(b))
	}
	if MessageBucketKey(a) == NormalizedMessage(a) {
		t.Error("expected MessageBucketKey to differ from the raw NormalizedMessage when DedupKey is set (distinct namespace)")
	}
}

// TestMessageBucketKey_FallsBackToNormalizedMessage guards the common case
// (no DedupKey set) — MessageBucketKey must behave exactly like
// NormalizedMessage.
func TestMessageBucketKey_FallsBackToNormalizedMessage(t *testing.T) {
	f := normFinding("ns", "app", "some message")
	if MessageBucketKey(f) != NormalizedMessage(f) {
		t.Errorf("expected MessageBucketKey to equal NormalizedMessage with no DedupKey, got %q vs %q", MessageBucketKey(f), NormalizedMessage(f))
	}
}
