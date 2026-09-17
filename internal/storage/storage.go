// Package storage defines the canonical multi-cluster data model and
// repository interfaces for kubectl-audit-server — the shared Postgres
// store that aggregates findings pushed from many clusters and/or tools
// (kubectl-audit itself, and OpenReports-emitting scanners), independent
// of any one cluster's local findings.json/triage-state.yaml.
//
// See the architecture plan for the full design rationale (fingerprinting/
// dedup algorithm, why "findings" carries no resolved state of its own,
// why cross-source findings are never merged). This package only defines
// the types and interfaces; internal/storage/postgres provides the actual
// implementation, kept separate so callers (the HTTP server, tests) depend
// on these interfaces, not a concrete database.
package storage

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound is returned by ClusterRepo.GetByID/GetByTokenHash and
// FindingRepo.GetFinding when no matching row exists — a single sentinel
// every repo implementation returns the same way, so callers (the future
// HTTP layer) can map it to 404 once, regardless of which repo raised it.
// TriageRepo.GetTriageEntry deliberately does NOT use this: a missing
// TriageEntry is the common, expected case (see its own doc comment) — an
// error there would make ordinary callers wrap every read in
// error-handling for a non-error condition.
var ErrNotFound = errors.New("not found")

// Cluster is one registered scan target — the unit findings/triage state
// is partitioned by. TokenHash is the sha256 of the bearer token issued at
// registration; the plaintext token is never stored (same principle this
// project already applies to Jira tokens — see triage.JiraClient's doc
// comment).
type Cluster struct {
	ID        uuid.UUID
	Name      string
	Endpoint  string
	Owner     string
	TokenHash string
	CreatedAt time.Time
}

// Scan is one ingestion event for one (Cluster, Source) pair — e.g. one
// `kubectl-audit scan` run, or one OpenReports Report/ClusterReport push.
// Source distinguishes which tool/format produced it ("kubectl-audit", or
// "openreports:<toolIdentifier>" — see the ingest adapters), since
// resolution (see FindingRepo.IngestScan) is scoped per (Cluster, Source),
// never across sources.
type Scan struct {
	ID             uuid.UUID
	ClusterID      uuid.UUID
	Source         string
	GeneratedAt    time.Time
	ClusterVersion string
	IngestedAt     time.Time
}

// Finding is one observed violation, keyed by (ClusterID, Source,
// Fingerprint) — see FindingRepo.IngestScan's doc comment for exactly how
// Fingerprint is derived per source. Deliberately a superset shape: native
// kubectl-audit findings populate every field; OpenReports-sourced
// findings leave Remediation/CIS/VerificationSteps empty, since that
// source has no equivalent data — see the architecture plan's "Triage
// from any source" section for why that's sufficient, not a gap to work
// around later.
//
// Finding carries no resolved/status field of its own — that's
// intentional (see TriageEntry/TriageStatusResolved): a Finding is a pure
// observation log (first seen, last seen, which scan last confirmed it),
// mirroring how internal/triage.Merge treats a bare finding locally today.
type Finding struct {
	ClusterID          uuid.UUID
	Source             string
	Fingerprint        string
	PolicyID           string
	Title              string
	Severity           string
	Category           string
	CIS                []string
	ResourceAPIVersion string
	ResourceKind       string
	ResourceNamespace  string
	ResourceName       string
	Message            string
	Remediation        string
	VerificationSteps  string
	// Properties holds source-specific data with no dedicated column —
	// e.g. OpenReports' own free-form ReportResult.properties map.
	Properties map[string]string
	FirstSeen  time.Time
	LastSeen   time.Time
	LastScanID uuid.UUID
}

// TriageStatus mirrors internal/triage.Status exactly (same string
// values), so the server and the local file-based TUI never present two
// different vocabularies for the same concept — see triage.Store's doc
// comment for how a future ServerStore reuses this directly.
type TriageStatus string

const (
	TriageStatusNew           TriageStatus = "new"
	TriageStatusConfirmed     TriageStatus = "confirmed"
	TriageStatusFalsePositive TriageStatus = "false_positive"
	TriageStatusWontFix       TriageStatus = "wont_fix"
	// TriageStatusResolved is set only by FindingRepo.IngestScan's
	// resolution pass, never directly by a caller — mirrors
	// internal/triage.StatusResolved's same "Merge-computed, not a human
	// action" contract, including its known quirk that a finding
	// reappearing later does not automatically restore whatever status
	// was set before resolution.
	TriageStatusResolved TriageStatus = "resolved"
)

// TriageEntry is one human (or automation-rule) decision attached to a
// Finding, keyed the same way: (ClusterID, Source, Fingerprint).
type TriageEntry struct {
	ClusterID    uuid.UUID
	Source       string
	Fingerprint  string
	Status       TriageStatus
	Note         string
	Reviewer     string
	JiraIssueKey string
	JiraIssueURL string
	UpdatedAt    time.Time
}

// FindingFilter narrows FindingRepo.ListFindings — every field is optional
// (zero value = no filter on that dimension).
type FindingFilter struct {
	Source   string
	Severity string
	Since    time.Time
}

// ClusterRepo manages registered clusters and their ingestion tokens.
// GetByID/GetByTokenHash return ErrNotFound (via errors.Is) when no
// matching cluster exists.
//
// Method names across ClusterRepo/FindingRepo/TriageRepo are kept globally
// unique on purpose (ListClusters, not List; GetFinding, not Get; ...): a
// single concrete type (postgres.Store) implements all three interfaces
// backed by one connection pool (see its package doc comment for why),
// and Go doesn't support overloading two same-named methods with
// different signatures on one type.
type ClusterRepo interface {
	Register(ctx context.Context, name, endpoint, owner, tokenHash string) (Cluster, error)
	GetByID(ctx context.Context, id uuid.UUID) (Cluster, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (Cluster, error)
	ListClusters(ctx context.Context) ([]Cluster, error)
}

// FindingRepo manages the findings/scans observation log.
type FindingRepo interface {
	// IngestScan records one scan's worth of findings for
	// scan.ClusterID/scan.Source: creates the scan row, upserts every
	// finding by (ClusterID, Source, Fingerprint) (first_seen preserved
	// across upserts, last_seen/last_scan_id updated), then marks any
	// existing TriageEntry for that same (ClusterID, Source) whose
	// Fingerprint is absent from findings as TriageStatusResolved — see
	// the architecture plan's fingerprinting/dedup design for why
	// resolution is scoped per-source, never across an entire cluster.
	// All of this happens in one transaction: a partial ingest (some
	// findings written, resolution not run) must never be observable.
	IngestScan(ctx context.Context, scan Scan, findings []Finding) (Scan, error)
	// GetFinding returns ErrNotFound (via errors.Is) when no matching
	// finding exists.
	GetFinding(ctx context.Context, clusterID uuid.UUID, source, fingerprint string) (Finding, error)
	ListFindings(ctx context.Context, clusterID uuid.UUID, filter FindingFilter) ([]Finding, error)
	// ListByResource is the cross-source/cross-cluster correlation query
	// — "everything anyone has flagged on this exact resource," never a
	// merge, just a shared lookup key. clusterID is optional (uuid.Nil
	// matches every cluster).
	ListByResource(ctx context.Context, clusterID uuid.UUID, kind, namespace, name string) ([]Finding, error)
	ListScans(ctx context.Context, clusterID uuid.UUID) ([]Scan, error)
}

// TriageRepo manages human/automation triage decisions.
type TriageRepo interface {
	// GetTriageEntry returns (entry, false, nil) — not an error — when no
	// entry exists yet for (clusterID, source, fingerprint), mirroring
	// internal/triage.Merge's "no matching Entry" case (a fresh, unset
	// TriageStatusNew, not a failure).
	GetTriageEntry(ctx context.Context, clusterID uuid.UUID, source, fingerprint string) (TriageEntry, bool, error)
	UpsertTriageEntry(ctx context.Context, entry TriageEntry) error
	ListTriageEntries(ctx context.Context, clusterID uuid.UUID) ([]TriageEntry, error)
}
