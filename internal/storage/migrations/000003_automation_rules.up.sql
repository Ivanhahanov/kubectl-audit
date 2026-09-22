CREATE TABLE automation_rules (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    trigger    JSONB NOT NULL DEFAULT '{}'::jsonb,
    action     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
