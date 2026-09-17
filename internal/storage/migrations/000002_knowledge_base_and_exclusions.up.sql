CREATE TABLE knowledge_base_entries (
    policy_id   TEXT PRIMARY KEY,
    title       TEXT NOT NULL DEFAULT '',
    category    TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    labels      TEXT[] NOT NULL DEFAULT '{}',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE exclusion_rules (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- NULL applies the rule to every cluster; a non-NULL value scopes it
    -- to one — see storage.ExclusionRuleRepo's doc comment.
    cluster_id UUID NULL REFERENCES clusters(id) ON DELETE CASCADE,
    policy_ids TEXT[] NOT NULL DEFAULT '{}',
    match      JSONB NOT NULL DEFAULT '{}'::jsonb,
    reason     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_exclusion_rules_cluster_id ON exclusion_rules (cluster_id);
