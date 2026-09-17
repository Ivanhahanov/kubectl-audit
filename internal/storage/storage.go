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
	// TriageStatusDuplicate and TriageStatusNeedsInfo complete parity with
	// internal/triage.Status's human-settable values (ValidHumanStatuses) —
	// the server accepts and round-trips every status the local file-based
	// TUI can set, not just a subset, so triage.ServerStore never has to
	// drop or remap a decision depending on where it's persisted.
	TriageStatusDuplicate TriageStatus = "duplicate"
	TriageStatusNeedsInfo TriageStatus = "needs_info"
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

// KnowledgeBaseEntry is one organization's own ticket-facing content for a
// check, centralizing what today lives in a local
// triage.knowledgeBaseFile — see findings.KnowledgeBaseEntry, whose fields
// this mirrors exactly, so a server-rendered Jira ticket (once automation
// exists — see the architecture plan's phase 6) matches whatever a local
// TUI user configured the same way would see.
type KnowledgeBaseEntry struct {
	PolicyID    string
	Title       string
	Category    string
	Description string
	Remediation string
	Labels      []string
	UpdatedAt   time.Time
}

// ExclusionMatch mirrors config.ExclusionMatch's JSON shape exactly (kept
// as JSONB in Postgres, not decomposed into columns, since it's opaque to
// every repo method — only internal/suppress's matching logic interprets
// it, the same as it does for the local audit.yaml today).
type ExclusionMatch struct {
	Kind      string            `json:"kind,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Name      string            `json:"name,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// ExclusionRule mirrors config.ExclusionRule, centralized. ClusterID nil
// means the rule applies to every cluster; a set ClusterID scopes it to
// one — e.g. a noisy finding that's a known false positive only on one
// specific cluster's setup, not organization-wide.
type ExclusionRule struct {
	ID        uuid.UUID
	ClusterID *uuid.UUID
	PolicyIDs []string
	Match     ExclusionMatch
	Reason    string
	CreatedAt time.Time
}

// KnowledgeBaseRepo centralizes knowledge-base entries. GetKnowledgeBaseEntry
// returns ErrNotFound (via errors.Is) when no entry exists for a PolicyID.
type KnowledgeBaseRepo interface {
	GetKnowledgeBaseEntry(ctx context.Context, policyID string) (KnowledgeBaseEntry, error)
	// PutKnowledgeBaseEntry creates or fully replaces the entry for
	// entry.PolicyID.
	PutKnowledgeBaseEntry(ctx context.Context, entry KnowledgeBaseEntry) error
}

// ExclusionRuleRepo centralizes exclusion (suppression) rules.
type ExclusionRuleRepo interface {
	CreateExclusionRule(ctx context.Context, rule ExclusionRule) (ExclusionRule, error)
	// ListExclusionRules returns every global rule (ClusterID nil) plus,
	// when clusterID is non-nil, every rule scoped to that one cluster —
	// the same "global defaults plus this cluster's own additions" set a
	// caller would need to actually apply exclusions, in one call.
	ListExclusionRules(ctx context.Context, clusterID *uuid.UUID) ([]ExclusionRule, error)
	// DeleteExclusionRule returns ErrNotFound (via errors.Is) when id
	// doesn't exist.
	DeleteExclusionRule(ctx context.Context, id uuid.UUID) error
}

// AutomationTrigger is the condition side of an AutomationRule — every set
// field must match for the rule to fire; an empty field imposes no
// constraint on that dimension. Kept as a small typed struct (marshaled to
// the trigger JSONB column) rather than a free-form map, so
// internal/server/automation's evaluator has a fixed, documented set of
// conditions to check instead of interpreting arbitrary keys.
type AutomationTrigger struct {
	// MinSeverity matches findings.Severity values ("LOW".."CRITICAL");
	// empty matches any severity.
	MinSeverity string `json:"minSeverity,omitempty"`
	// Status restricts to one TriageStatus (e.g. "confirmed"); empty
	// matches any status including untriaged ("new").
	Status string `json:"status,omitempty"`
	// Source restricts to one scan source (e.g. "kubectl-audit"); empty
	// matches any source.
	Source string `json:"source,omitempty"`
	// NoJiraLinkForHours matches only TriageEntries with no JiraIssueKey
	// whose UpdatedAt is at least this many hours in the past — the "been
	// sitting confirmed with nothing filed" condition. Zero imposes no
	// time constraint.
	NoJiraLinkForHours int `json:"noJiraLinkForHours,omitempty"`
}

// AutomationAction is the effect side of an AutomationRule. Type is
// extensible (validated by internal/server/automation, not this package):
// "file_jira" today, and "agent_triage" reserved for AI-agent-driven
// triage per the architecture plan's phase 6 design — see that package's
// doc comment for which types actually execute vs. are recorded only.
type AutomationAction struct {
	Type string `json:"type"`
	// Prompt/Tools are agent_triage-specific: the instruction an agent
	// gets and which MCP tools (see the kubectl-audit inspect/MCP design)
	// it may call while deciding. Ignored by other action types.
	Prompt string   `json:"prompt,omitempty"`
	Tools  []string `json:"tools,omitempty"`
}

// AutomationRule is one "when X, do Y" policy a background evaluator
// checks periodically against open findings/triage entries.
type AutomationRule struct {
	ID        uuid.UUID
	Name      string
	Enabled   bool
	Trigger   AutomationTrigger
	Action    AutomationAction
	CreatedAt time.Time
}

// AutomationRuleRepo manages automation rules.
type AutomationRuleRepo interface {
	CreateAutomationRule(ctx context.Context, rule AutomationRule) (AutomationRule, error)
	// GetAutomationRule returns ErrNotFound (via errors.Is) when id
	// doesn't exist.
	GetAutomationRule(ctx context.Context, id uuid.UUID) (AutomationRule, error)
	ListAutomationRules(ctx context.Context) ([]AutomationRule, error)
	UpdateAutomationRule(ctx context.Context, rule AutomationRule) error
	DeleteAutomationRule(ctx context.Context, id uuid.UUID) error
}

// AuditRequestStatus is where one audit request sits in its lifecycle.
type AuditRequestStatus string

const (
	AuditRequestPending   AuditRequestStatus = "pending"
	AuditRequestApproved  AuditRequestStatus = "approved"
	AuditRequestRunning   AuditRequestStatus = "running"
	AuditRequestCompleted AuditRequestStatus = "completed"
	AuditRequestFailed    AuditRequestStatus = "failed"
)

// AuditRequest is a manual or recurring request to run a scan against a
// cluster — "заявка" in the architecture plan's original framing, covering
// both a one-off human request and (via ScheduledCron) a recurring one.
// Approving a pending request is what actually triggers a scan — see
// internal/server/automation.PipelineTrigger.
type AuditRequest struct {
	ID                    uuid.UUID
	ClusterID             uuid.UUID
	RequestedBy           string
	Reason                string
	Status                AuditRequestStatus
	TektonPipelineRunName string
	// ScheduledCron, when set, marks this as a template a future recurring
	// worker re-instantiates (e.g. "0 3 * * *") rather than a one-off
	// request — stored now so the schema doesn't need to change when that
	// worker is built, even though nothing expands it yet.
	ScheduledCron *string
	CreatedAt     time.Time
}

// AuditRequestRepo manages audit requests.
type AuditRequestRepo interface {
	CreateAuditRequest(ctx context.Context, req AuditRequest) (AuditRequest, error)
	// GetAuditRequest returns ErrNotFound (via errors.Is) when id doesn't
	// exist.
	GetAuditRequest(ctx context.Context, id uuid.UUID) (AuditRequest, error)
	ListAuditRequests(ctx context.Context, clusterID *uuid.UUID) ([]AuditRequest, error)
	UpdateAuditRequest(ctx context.Context, req AuditRequest) error
}
