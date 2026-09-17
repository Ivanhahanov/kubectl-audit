package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
	"github.com/ivanhahanov/kubectl-audit/internal/storage/postgres"
)

// testStore is shared across every test in this file, backed by one
// testcontainers-managed Postgres instance — starting a fresh container
// per test would make this suite take minutes instead of seconds. Each
// test registers its own uniquely-named cluster (see newTestCluster) so
// sharing one database never causes cross-test interference: every table
// here is scoped by cluster_id.
var testStore *postgres.Store

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	ctx := context.Background()
	ctr, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("kubectl_audit_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "starting postgres test container:", err)
		return 1
	}
	defer func() { _ = ctr.Terminate(ctx) }()

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintln(os.Stderr, "getting connection string:", err)
		return 1
	}

	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "opening store (runs migrations):", err)
		return 1
	}
	defer store.Close()

	testStore = store
	return m.Run()
}

// newTestCluster registers a cluster with a unique name so this test's
// data can never collide with another test's, despite sharing one
// container/database for the whole file.
func newTestCluster(t *testing.T) storage.Cluster {
	t.Helper()
	c, err := testStore.Register(context.Background(), "cluster-"+uuid.NewString(), "https://example.invalid:6443", "test-owner", "tokenhash-"+uuid.NewString())
	if err != nil {
		t.Fatalf("registering test cluster: %v", err)
	}
	return c
}

func TestClusterRepo_RegisterAndLookup(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t)

	byID, err := testStore.GetByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if byID.Name != c.Name || byID.TokenHash != c.TokenHash {
		t.Errorf("expected GetByID to return the registered cluster, got %+v", byID)
	}

	byToken, err := testStore.GetByTokenHash(ctx, c.TokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash: %v", err)
	}
	if byToken.ID != c.ID {
		t.Errorf("expected GetByTokenHash to return the same cluster, got %+v", byToken)
	}

	list, err := testStore.ListClusters(ctx)
	if err != nil {
		t.Fatalf("ListClusters: %v", err)
	}
	found := false
	for _, lc := range list {
		if lc.ID == c.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ListClusters to include the registered cluster %s", c.ID)
	}
}

func TestClusterRepo_GetByID_NotFound(t *testing.T) {
	_, err := testStore.GetByID(context.Background(), uuid.New())
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("expected storage.ErrNotFound, got %v", err)
	}
}

func TestClusterRepo_GetByTokenHash_NotFound(t *testing.T) {
	_, err := testStore.GetByTokenHash(context.Background(), "no-such-token-hash")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("expected storage.ErrNotFound, got %v", err)
	}
}

// testFinding builds a minimal, valid storage.Finding for a given
// cluster/source/fingerprint — helper shared by the FindingRepo tests
// below.
func testFinding(clusterID uuid.UUID, source, fingerprint string) storage.Finding {
	return storage.Finding{
		ClusterID:         clusterID,
		Source:            source,
		Fingerprint:       fingerprint,
		PolicyID:          "workload.no-latest-tag",
		Title:             "Uses the latest tag",
		Severity:          "HIGH",
		Category:          "workload-security",
		ResourceKind:      "Deployment",
		ResourceNamespace: "default",
		ResourceName:      "app",
		Message:           "container image uses the latest tag",
	}
}

func TestFindingRepo_GetFinding_NotFound(t *testing.T) {
	c := newTestCluster(t)
	_, err := testStore.GetFinding(context.Background(), c.ID, "kubectl-audit", "no-such-fingerprint")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("expected storage.ErrNotFound, got %v", err)
	}
}

// TestFindingRepo_IngestScan_UpsertIsIdempotent is the "same-source
// idempotency" property from the dedup design: re-ingesting the same
// fingerprint in a later scan must update the row in place (last_seen/
// last_scan_id move forward, first_seen stays put), never create a
// duplicate.
func TestFindingRepo_IngestScan_UpsertIsIdempotent(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t)
	f := testFinding(c.ID, "kubectl-audit", "fp-1")

	gen1 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	scan1, err := testStore.IngestScan(ctx, storage.Scan{ClusterID: c.ID, Source: "kubectl-audit", GeneratedAt: gen1}, []storage.Finding{f})
	if err != nil {
		t.Fatalf("first IngestScan: %v", err)
	}

	gen2 := time.Now().UTC().Truncate(time.Second)
	scan2, err := testStore.IngestScan(ctx, storage.Scan{ClusterID: c.ID, Source: "kubectl-audit", GeneratedAt: gen2}, []storage.Finding{f})
	if err != nil {
		t.Fatalf("second IngestScan: %v", err)
	}

	got, err := testStore.GetFinding(ctx, c.ID, "kubectl-audit", "fp-1")
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if !got.FirstSeen.Equal(gen1) {
		t.Errorf("expected first_seen preserved at %v across re-ingestion, got %v", gen1, got.FirstSeen)
	}
	if !got.LastSeen.Equal(gen2) {
		t.Errorf("expected last_seen updated to %v, got %v", gen2, got.LastSeen)
	}
	if got.LastScanID != scan2.ID {
		t.Errorf("expected last_scan_id to point at the second scan %s, got %s", scan2.ID, got.LastScanID)
	}

	all, err := testStore.ListFindings(ctx, c.ID, storage.FindingFilter{})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	count := 0
	for _, lf := range all {
		if lf.Fingerprint == "fp-1" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 row for fp-1 after two ingests, got %d", count)
	}
	_ = scan1 // only scan2's identity matters for this assertion
}

// TestFindingRepo_IngestScan_ResolvesMissingFindings is the resolution
// half of the dedup design: a triaged finding that disappears from the
// next scan (of the same cluster+source) gets its TriageEntry marked
// resolved, mirroring internal/triage.Merge's local behavior — the
// finding it disappeared from an untouched finding is simply absent from
// ListFindings, no phantom "resolved finding" row is created.
func TestFindingRepo_IngestScan_ResolvesMissingFindings(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t)
	fa := testFinding(c.ID, "kubectl-audit", "fp-a")
	fb := testFinding(c.ID, "kubectl-audit", "fp-b")

	if _, err := testStore.IngestScan(ctx, storage.Scan{ClusterID: c.ID, Source: "kubectl-audit", GeneratedAt: time.Now().UTC()}, []storage.Finding{fa, fb}); err != nil {
		t.Fatalf("first IngestScan: %v", err)
	}

	// A human confirms fp-a before it disappears.
	if err := testStore.UpsertTriageEntry(ctx, storage.TriageEntry{
		ClusterID: c.ID, Source: "kubectl-audit", Fingerprint: "fp-a", Status: storage.TriageStatusConfirmed,
	}); err != nil {
		t.Fatalf("UpsertTriageEntry: %v", err)
	}

	// Second scan only sees fp-b — fp-a was fixed.
	if _, err := testStore.IngestScan(ctx, storage.Scan{ClusterID: c.ID, Source: "kubectl-audit", GeneratedAt: time.Now().UTC()}, []storage.Finding{fb}); err != nil {
		t.Fatalf("second IngestScan: %v", err)
	}

	entry, ok, err := testStore.GetTriageEntry(ctx, c.ID, "kubectl-audit", "fp-a")
	if err != nil {
		t.Fatalf("GetTriageEntry: %v", err)
	}
	if !ok {
		t.Fatal("expected a triage entry for fp-a to still exist")
	}
	if entry.Status != storage.TriageStatusResolved {
		t.Errorf("expected fp-a's status to become %q once it disappeared, got %q", storage.TriageStatusResolved, entry.Status)
	}

	// fp-b was never triaged and is still present — no triage entry
	// should have been created for it.
	_, ok, err = testStore.GetTriageEntry(ctx, c.ID, "kubectl-audit", "fp-b")
	if err != nil {
		t.Fatalf("GetTriageEntry fp-b: %v", err)
	}
	if ok {
		t.Error("expected no triage entry to exist for an untouched, still-present finding")
	}
}

// TestFindingRepo_IngestScan_ResolutionScopedPerSource guards the
// deliberate design point that resolution never crosses source
// boundaries: an OpenReports-sourced finding must never be resolved just
// because a kubectl-audit scan of the same cluster didn't mention it.
func TestFindingRepo_IngestScan_ResolutionScopedPerSource(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t)
	fp := "shared-looking-fingerprint" // deliberately the same string across sources, to prove source scoping, not string uniqueness, is what matters

	nativeFinding := testFinding(c.ID, "kubectl-audit", fp)
	if _, err := testStore.IngestScan(ctx, storage.Scan{ClusterID: c.ID, Source: "kubectl-audit", GeneratedAt: time.Now().UTC()}, []storage.Finding{nativeFinding}); err != nil {
		t.Fatalf("ingesting kubectl-audit scan: %v", err)
	}
	if err := testStore.UpsertTriageEntry(ctx, storage.TriageEntry{
		ClusterID: c.ID, Source: "kubectl-audit", Fingerprint: fp, Status: storage.TriageStatusConfirmed,
	}); err != nil {
		t.Fatalf("UpsertTriageEntry: %v", err)
	}

	// An unrelated OpenReports source scans the same cluster and reports
	// nothing at all — this must NOT resolve kubectl-audit's entry.
	if _, err := testStore.IngestScan(ctx, storage.Scan{ClusterID: c.ID, Source: "openreports:kyverno", GeneratedAt: time.Now().UTC()}, nil); err != nil {
		t.Fatalf("ingesting empty openreports scan: %v", err)
	}

	entry, ok, err := testStore.GetTriageEntry(ctx, c.ID, "kubectl-audit", fp)
	if err != nil {
		t.Fatalf("GetTriageEntry: %v", err)
	}
	if !ok {
		t.Fatal("expected the kubectl-audit triage entry to still exist")
	}
	if entry.Status != storage.TriageStatusConfirmed {
		t.Errorf("expected the kubectl-audit entry to remain %q (unaffected by an unrelated source's scan), got %q", storage.TriageStatusConfirmed, entry.Status)
	}
}

// TestFindingRepo_ListByResource_CrossSourceNoCollision guards the other
// deliberate design point: two different sources flagging the exact same
// resource never collapse into one row — ListByResource surfaces both,
// distinct.
func TestFindingRepo_ListByResource_CrossSourceNoCollision(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t)
	nativeFinding := testFinding(c.ID, "kubectl-audit", "native-fp")
	nativeFinding.ResourceNamespace = "shared-ns"
	nativeFinding.ResourceName = "shared-app"
	orFinding := testFinding(c.ID, "openreports:kyverno", "or-fp")
	orFinding.ResourceNamespace = "shared-ns"
	orFinding.ResourceName = "shared-app"

	if _, err := testStore.IngestScan(ctx, storage.Scan{ClusterID: c.ID, Source: "kubectl-audit", GeneratedAt: time.Now().UTC()}, []storage.Finding{nativeFinding}); err != nil {
		t.Fatalf("ingesting kubectl-audit scan: %v", err)
	}
	if _, err := testStore.IngestScan(ctx, storage.Scan{ClusterID: c.ID, Source: "openreports:kyverno", GeneratedAt: time.Now().UTC()}, []storage.Finding{orFinding}); err != nil {
		t.Fatalf("ingesting openreports scan: %v", err)
	}

	got, err := testStore.ListByResource(ctx, c.ID, "Deployment", "shared-ns", "shared-app")
	if err != nil {
		t.Fatalf("ListByResource: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct rows (one per source) for the same resource, got %d: %+v", len(got), got)
	}
	sources := map[string]bool{}
	for _, f := range got {
		sources[f.Source] = true
	}
	if !sources["kubectl-audit"] || !sources["openreports:kyverno"] {
		t.Errorf("expected both sources represented, got %+v", sources)
	}
}

func TestTriageRepo_GetTriageEntry_ReturnsFalseWhenMissing(t *testing.T) {
	c := newTestCluster(t)
	_, ok, err := testStore.GetTriageEntry(context.Background(), c.ID, "kubectl-audit", "never-triaged")
	if err != nil {
		t.Fatalf("GetTriageEntry: %v", err)
	}
	if ok {
		t.Error("expected ok=false for a fingerprint with no triage entry, not an error")
	}
}

func TestTriageRepo_UpsertAndList(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t)
	f := testFinding(c.ID, "kubectl-audit", "fp-triage")
	if _, err := testStore.IngestScan(ctx, storage.Scan{ClusterID: c.ID, Source: "kubectl-audit", GeneratedAt: time.Now().UTC()}, []storage.Finding{f}); err != nil {
		t.Fatalf("IngestScan: %v", err)
	}

	entry := storage.TriageEntry{
		ClusterID: c.ID, Source: "kubectl-audit", Fingerprint: "fp-triage",
		Status: storage.TriageStatusConfirmed, Note: "tracked in SEC-1", Reviewer: "alice",
	}
	if err := testStore.UpsertTriageEntry(ctx, entry); err != nil {
		t.Fatalf("UpsertTriageEntry (insert): %v", err)
	}

	got, ok, err := testStore.GetTriageEntry(ctx, c.ID, "kubectl-audit", "fp-triage")
	if err != nil || !ok {
		t.Fatalf("GetTriageEntry: ok=%v err=%v", ok, err)
	}
	if got.Status != storage.TriageStatusConfirmed || got.Note != "tracked in SEC-1" || got.Reviewer != "alice" {
		t.Errorf("expected the upserted fields to round-trip, got %+v", got)
	}

	// Upsert again with a different status — must update in place, not
	// create a second row.
	entry.Status = storage.TriageStatusWontFix
	entry.JiraIssueKey = "SEC-1"
	if err := testStore.UpsertTriageEntry(ctx, entry); err != nil {
		t.Fatalf("UpsertTriageEntry (update): %v", err)
	}

	list, err := testStore.ListTriageEntries(ctx, c.ID)
	if err != nil {
		t.Fatalf("ListTriageEntries: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected exactly 1 triage entry after two upserts of the same key, got %d", len(list))
	}
	if list[0].Status != storage.TriageStatusWontFix || list[0].JiraIssueKey != "SEC-1" {
		t.Errorf("expected the second upsert's fields to win, got %+v", list[0])
	}
}
