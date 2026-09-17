CREATE TABLE automation_rules (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    trigger    JSONB NOT NULL DEFAULT '{}'::jsonb,
    action     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_requests (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id              UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    requested_by            TEXT NOT NULL DEFAULT '',
    reason                  TEXT NOT NULL DEFAULT '',
    status                  TEXT NOT NULL DEFAULT 'pending',
    tekton_pipelinerun_name TEXT NOT NULL DEFAULT '',
    scheduled_cron          TEXT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_requests_cluster_id ON audit_requests (cluster_id);
