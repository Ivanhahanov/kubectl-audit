-- Phase 1 of the kubectl-audit-server architecture plan: clusters, scans,
-- findings, triage_entries only. knowledge_base_entries/exclusion_rules
-- (phase 5) and automation_rules/audit_requests (phase 6) arrive in later
-- migrations alongside the code that actually uses them, rather than
-- sitting unused and untested from day one.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE clusters (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL UNIQUE,
    endpoint   TEXT NOT NULL DEFAULT '',
    owner      TEXT NOT NULL DEFAULT '',
    -- sha256 of the bearer token issued at registration; the plaintext
    -- token is never stored, same principle already applied to Jira
    -- tokens elsewhere in this project.
    token_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id      UUID NOT NULL REFERENCES clusters (id) ON DELETE CASCADE,
    -- "kubectl-audit" or "openreports:<toolIdentifier>" — see
    -- FindingRepo.IngestScan's doc comment for why resolution is scoped
    -- per (cluster_id, source), never across an entire cluster.
    source          TEXT NOT NULL,
    generated_at    TIMESTAMPTZ NOT NULL,
    cluster_version TEXT NOT NULL DEFAULT '',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX scans_cluster_id_idx ON scans (cluster_id);

CREATE TABLE findings (
    cluster_id           UUID NOT NULL REFERENCES clusters (id) ON DELETE CASCADE,
    source               TEXT NOT NULL,
    -- Native kubectl-audit: the finding's own cluster-scoped id from
    -- findings.json (see findings.ScopeID), reused as-is. OpenReports:
    -- sha256(cluster_id|policy|rule|resource identity), computed at
    -- ingestion. source is part of the primary key itself (not just a
    -- column) so two different tools' fingerprints can never collide by
    -- construction, regardless of hash input details.
    fingerprint          TEXT NOT NULL,
    policy_id            TEXT NOT NULL,
    title                TEXT NOT NULL DEFAULT '',
    severity             TEXT NOT NULL,
    category             TEXT NOT NULL DEFAULT '',
    cis                  TEXT[] NOT NULL DEFAULT '{}',
    resource_api_version TEXT NOT NULL DEFAULT '',
    resource_kind        TEXT NOT NULL,
    resource_namespace   TEXT NOT NULL DEFAULT '',
    resource_name        TEXT NOT NULL,
    message              TEXT NOT NULL,
    -- Left empty for OpenReports-sourced findings, which have no
    -- equivalent data — see storage.Finding's doc comment.
    remediation          TEXT NOT NULL DEFAULT '',
    verification_steps   TEXT NOT NULL DEFAULT '',
    properties           JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen           TIMESTAMPTZ NOT NULL,
    last_seen            TIMESTAMPTZ NOT NULL,
    last_scan_id         UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    PRIMARY KEY (cluster_id, source, fingerprint)
);

-- Cross-source/cross-cluster correlation query: "everything anyone has
-- flagged on this exact resource" — never a merge, just a shared lookup.
CREATE INDEX findings_resource_idx ON findings (cluster_id, resource_kind, resource_namespace, resource_name);

CREATE TABLE triage_entries (
    cluster_id     UUID NOT NULL,
    source         TEXT NOT NULL,
    fingerprint    TEXT NOT NULL,
    -- Mirrors internal/triage.Status exactly: new|confirmed|
    -- false_positive|wont_fix|resolved. "resolved" is set only by
    -- FindingRepo.IngestScan's resolution pass, never directly by a
    -- human/API caller.
    status         TEXT NOT NULL DEFAULT 'new',
    note           TEXT NOT NULL DEFAULT '',
    reviewer       TEXT NOT NULL DEFAULT '',
    jira_issue_key TEXT NOT NULL DEFAULT '',
    jira_issue_url TEXT NOT NULL DEFAULT '',
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cluster_id, source, fingerprint),
    FOREIGN KEY (cluster_id, source, fingerprint)
        REFERENCES findings (cluster_id, source, fingerprint) ON DELETE CASCADE
);
