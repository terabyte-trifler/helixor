-- =============================================================================
-- Migration 0008 — Composite Scorer v2 metadata.
--
-- Day 13 adds composite-score confidence, gaming detection, five-dimension
-- contribution columns, and guard-rail provenance. The existing MVP schema
-- already has `agent_scores`, so this migration must be additive and safe to
-- run after 0003 instead of trying to recreate the table with a new shape.
-- =============================================================================

INSERT INTO schema_version (version, description) VALUES
    (8, 'Composite Scorer v2: confidence, gaming flag, 5-dimension breakdown')
ON CONFLICT (version) DO NOTHING;


-- Keep the original `alert` column for backward compatibility, but add the
-- clearer v2 alias used by dashboards and future repositories.
ALTER TABLE agent_scores
    ADD COLUMN IF NOT EXISTS alert_tier TEXT;

UPDATE agent_scores
SET alert_tier = alert
WHERE alert_tier IS NULL;

ALTER TABLE agent_scores
    ALTER COLUMN alert_tier SET DEFAULT 'YELLOW',
    ALTER COLUMN alert_tier SET NOT NULL;


-- Per-dimension weighted contributions to the pre-guard-rail aggregate.
-- Backfill existing rows from the MVP breakdown where possible.
ALTER TABLE agent_scores
    ADD COLUMN IF NOT EXISTS dim1 INTEGER,
    ADD COLUMN IF NOT EXISTS dim2 INTEGER,
    ADD COLUMN IF NOT EXISTS dim3 INTEGER,
    ADD COLUMN IF NOT EXISTS dim4 INTEGER,
    ADD COLUMN IF NOT EXISTS dim5 INTEGER;

UPDATE agent_scores
SET
    dim1 = COALESCE(dim1, success_rate_score),
    dim2 = COALESCE(dim2, stability_score),
    dim3 = COALESCE(dim3, 0),
    dim4 = COALESCE(dim4, consistency_score),
    dim5 = COALESCE(dim5, 0)
WHERE dim1 IS NULL
   OR dim2 IS NULL
   OR dim3 IS NULL
   OR dim4 IS NULL
   OR dim5 IS NULL;

ALTER TABLE agent_scores
    ALTER COLUMN dim1 SET DEFAULT 0,
    ALTER COLUMN dim2 SET DEFAULT 0,
    ALTER COLUMN dim3 SET DEFAULT 0,
    ALTER COLUMN dim4 SET DEFAULT 0,
    ALTER COLUMN dim5 SET DEFAULT 0,
    ALTER COLUMN dim1 SET NOT NULL,
    ALTER COLUMN dim2 SET NOT NULL,
    ALTER COLUMN dim3 SET NOT NULL,
    ALTER COLUMN dim4 SET NOT NULL,
    ALTER COLUMN dim5 SET NOT NULL;


-- Day-13 additions.
ALTER TABLE agent_scores
    ADD COLUMN IF NOT EXISTS confidence INTEGER,
    ADD COLUMN IF NOT EXISTS gaming_flag BOOLEAN,
    ADD COLUMN IF NOT EXISTS gaming_drop_fraction DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS feature_schema_fp TEXT,
    ADD COLUMN IF NOT EXISTS scoring_schema_fp TEXT,
    ADD COLUMN IF NOT EXISTS aggregated_flags BIGINT,
    ADD COLUMN IF NOT EXISTS delta_clamped BOOLEAN;

UPDATE agent_scores
SET
    confidence = COALESCE(confidence, 1000),
    gaming_flag = COALESCE(gaming_flag, FALSE),
    gaming_drop_fraction = COALESCE(gaming_drop_fraction, 0.0),
    feature_schema_fp = COALESCE(feature_schema_fp, ''),
    scoring_schema_fp = COALESCE(scoring_schema_fp, ''),
    aggregated_flags = COALESCE(aggregated_flags, 0),
    delta_clamped = COALESCE(delta_clamped, guard_rail_applied)
WHERE confidence IS NULL
   OR gaming_flag IS NULL
   OR gaming_drop_fraction IS NULL
   OR feature_schema_fp IS NULL
   OR scoring_schema_fp IS NULL
   OR aggregated_flags IS NULL
   OR delta_clamped IS NULL;

ALTER TABLE agent_scores
    ALTER COLUMN confidence SET DEFAULT 1000,
    ALTER COLUMN gaming_flag SET DEFAULT FALSE,
    ALTER COLUMN gaming_drop_fraction SET DEFAULT 0.0,
    ALTER COLUMN feature_schema_fp SET DEFAULT '',
    ALTER COLUMN scoring_schema_fp SET DEFAULT '',
    ALTER COLUMN aggregated_flags SET DEFAULT 0,
    ALTER COLUMN delta_clamped SET DEFAULT FALSE,
    ALTER COLUMN confidence SET NOT NULL,
    ALTER COLUMN gaming_flag SET NOT NULL,
    ALTER COLUMN gaming_drop_fraction SET NOT NULL,
    ALTER COLUMN feature_schema_fp SET NOT NULL,
    ALTER COLUMN scoring_schema_fp SET NOT NULL,
    ALTER COLUMN aggregated_flags SET NOT NULL,
    ALTER COLUMN delta_clamped SET NOT NULL;


-- Constraints are added idempotently via pg_constraint checks because
-- PostgreSQL does not support ADD CONSTRAINT IF NOT EXISTS.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'agent_scores_confidence_range'
    ) THEN
        ALTER TABLE agent_scores
            ADD CONSTRAINT agent_scores_confidence_range
            CHECK (confidence >= 0 AND confidence <= 1000);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'agent_scores_alert_tier_v2'
    ) THEN
        ALTER TABLE agent_scores
            ADD CONSTRAINT agent_scores_alert_tier_v2
            CHECK (alert_tier IN ('GREEN', 'YELLOW', 'RED'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'agent_scores_dims_nonneg'
    ) THEN
        ALTER TABLE agent_scores
            ADD CONSTRAINT agent_scores_dims_nonneg
            CHECK (dim1 >= 0 AND dim2 >= 0 AND dim3 >= 0
                   AND dim4 >= 0 AND dim5 >= 0);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'agent_scores_gaming_drop_range'
    ) THEN
        ALTER TABLE agent_scores
            ADD CONSTRAINT agent_scores_gaming_drop_range
            CHECK (gaming_drop_fraction >= 0.0 AND gaming_drop_fraction <= 1.0);
    END IF;
END $$;


CREATE INDEX IF NOT EXISTS idx_agent_scores_wallet_time
    ON agent_scores (agent_wallet, computed_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_scores_alert_tier
    ON agent_scores (alert_tier, computed_at DESC);

COMMENT ON COLUMN agent_scores.confidence IS
    'Data-sufficiency confidence 0-1000; low for new/sparse agents.';
COMMENT ON COLUMN agent_scores.gaming_flag IS
    'True if behavioural entropy collapsed >25% vs baseline.';
COMMENT ON COLUMN agent_scores.delta_clamped IS
    'True if the 200-point score delta guard rail changed the emitted score.';
