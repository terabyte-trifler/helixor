-- =============================================================================
-- Migration 0008 — Composite Scorer v2.
--
-- Day 13 makes the composite scorer real: a 0-1000 score with a full
-- five-dimension breakdown, a data-sufficiency confidence score, and a
-- gaming flag (behavioural-entropy collapse). This migration creates the
-- v2 `agent_scores` table that persists those outputs.
--
-- NOTE ON NUMBERING: the Doc-2 brief labels this migration "0007", but
-- 0007 was already taken by the Day-6 baseline-v3 migration. This file is
-- 0008 — the next free ordinal — and is otherwise exactly the scores-v2
-- migration the brief describes.
--
-- The score column carries the value AFTER the 200-point delta guard rail;
-- dim1..dim5 carry each dimension's raw 0..max contribution to the
-- pre-rail aggregate, so an auditor can reconstruct the weighting.
-- =============================================================================

INSERT INTO schema_version (version, description) VALUES
    (8, 'Composite Scorer v2: agent_scores with 5-dimension breakdown, confidence, gaming flag')
ON CONFLICT (version) DO NOTHING;


-- ── agent_scores — the v2 score table ───────────────────────────────────────
--
-- Append-only history: every scoring run inserts a row. The latest row per
-- agent (by computed_at) is the agent's current trust score.

CREATE TABLE IF NOT EXISTS agent_scores (
    id           BIGSERIAL PRIMARY KEY,
    agent_wallet TEXT      NOT NULL,
    score        INTEGER   NOT NULL,
    computed_at  TIMESTAMPTZ NOT NULL
);

ALTER TABLE agent_scores
    ADD COLUMN IF NOT EXISTS alert_tier              TEXT,
    ADD COLUMN IF NOT EXISTS dim1                    INTEGER,
    ADD COLUMN IF NOT EXISTS dim2                    INTEGER,
    ADD COLUMN IF NOT EXISTS dim3                    INTEGER,
    ADD COLUMN IF NOT EXISTS dim4                    INTEGER,
    ADD COLUMN IF NOT EXISTS dim5                    INTEGER,
    ADD COLUMN IF NOT EXISTS confidence              INTEGER,
    ADD COLUMN IF NOT EXISTS gaming_flag             BOOLEAN,
    ADD COLUMN IF NOT EXISTS scoring_algo_version    INTEGER,
    ADD COLUMN IF NOT EXISTS baseline_stats_hash     TEXT,
    ADD COLUMN IF NOT EXISTS feature_schema_fp       TEXT,
    ADD COLUMN IF NOT EXISTS scoring_schema_fp       TEXT,
    ADD COLUMN IF NOT EXISTS aggregated_flags        BIGINT,
    ADD COLUMN IF NOT EXISTS delta_clamped           BOOLEAN,
    ADD COLUMN IF NOT EXISTS inserted_at             TIMESTAMPTZ DEFAULT now();

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'agent_scores' AND column_name = 'success_rate_score'
    ) THEN
        EXECUTE 'UPDATE agent_scores
                 SET alert_tier = COALESCE(alert_tier, alert, ''GREEN''),
                     dim1 = COALESCE(dim1, success_rate_score, 0),
                     dim2 = COALESCE(dim2, consistency_score, 0),
                     dim3 = COALESCE(dim3, stability_score, 0),
                     dim4 = COALESCE(dim4, 0),
                     dim5 = COALESCE(dim5, 0),
                     confidence = COALESCE(confidence, 1000),
                     gaming_flag = COALESCE(gaming_flag, FALSE),
                     scoring_algo_version = COALESCE(scoring_algo_version, 1),
                     baseline_stats_hash = COALESCE(baseline_stats_hash, baseline_hash, ''''),
                     feature_schema_fp = COALESCE(feature_schema_fp, ''''),
                     scoring_schema_fp = COALESCE(scoring_schema_fp, ''''),
                     aggregated_flags = COALESCE(aggregated_flags, 0),
                     delta_clamped = COALESCE(delta_clamped, guard_rail_applied, FALSE),
                     inserted_at = COALESCE(inserted_at, computed_at, now())';
    ELSE
        EXECUTE 'UPDATE agent_scores
                 SET alert_tier = COALESCE(alert_tier, ''GREEN''),
                     dim1 = COALESCE(dim1, 0),
                     dim2 = COALESCE(dim2, 0),
                     dim3 = COALESCE(dim3, 0),
                     dim4 = COALESCE(dim4, 0),
                     dim5 = COALESCE(dim5, 0),
                     confidence = COALESCE(confidence, 1000),
                     gaming_flag = COALESCE(gaming_flag, FALSE),
                     scoring_algo_version = COALESCE(scoring_algo_version, 1),
                     baseline_stats_hash = COALESCE(baseline_stats_hash, ''''),
                     feature_schema_fp = COALESCE(feature_schema_fp, ''''),
                     scoring_schema_fp = COALESCE(scoring_schema_fp, ''''),
                     aggregated_flags = COALESCE(aggregated_flags, 0),
                     delta_clamped = COALESCE(delta_clamped, FALSE),
                     inserted_at = COALESCE(inserted_at, computed_at, now())';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION sync_agent_scores_v2_defaults()
RETURNS TRIGGER AS $$
BEGIN
    NEW.alert_tier := COALESCE(NEW.alert_tier, NEW.alert, 'GREEN');
    NEW.dim1 := COALESCE(NEW.dim1, NEW.success_rate_score, 0);
    NEW.dim2 := COALESCE(NEW.dim2, NEW.consistency_score, 0);
    NEW.dim3 := COALESCE(NEW.dim3, NEW.stability_score, 0);
    NEW.dim4 := COALESCE(NEW.dim4, 0);
    NEW.dim5 := COALESCE(NEW.dim5, 0);
    NEW.confidence := COALESCE(NEW.confidence, 1000);
    NEW.gaming_flag := COALESCE(NEW.gaming_flag, FALSE);
    NEW.scoring_algo_version := COALESCE(NEW.scoring_algo_version, 1);
    NEW.baseline_stats_hash := COALESCE(NEW.baseline_stats_hash, NEW.baseline_hash, '');
    NEW.feature_schema_fp := COALESCE(NEW.feature_schema_fp, '');
    NEW.scoring_schema_fp := COALESCE(NEW.scoring_schema_fp, '');
    NEW.aggregated_flags := COALESCE(NEW.aggregated_flags, 0);
    NEW.delta_clamped := COALESCE(NEW.delta_clamped, NEW.guard_rail_applied, FALSE);
    NEW.inserted_at := COALESCE(NEW.inserted_at, NEW.computed_at, now());
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_agent_scores_v2_defaults ON agent_scores;
CREATE TRIGGER trg_agent_scores_v2_defaults
    BEFORE INSERT OR UPDATE ON agent_scores
    FOR EACH ROW EXECUTE FUNCTION sync_agent_scores_v2_defaults();

ALTER TABLE agent_scores
    ALTER COLUMN alert_tier SET NOT NULL,
    ALTER COLUMN dim1 SET NOT NULL,
    ALTER COLUMN dim2 SET NOT NULL,
    ALTER COLUMN dim3 SET NOT NULL,
    ALTER COLUMN dim4 SET NOT NULL,
    ALTER COLUMN dim5 SET NOT NULL,
    ALTER COLUMN confidence SET NOT NULL,
    ALTER COLUMN gaming_flag SET NOT NULL,
    ALTER COLUMN scoring_algo_version SET NOT NULL,
    ALTER COLUMN baseline_stats_hash SET NOT NULL,
    ALTER COLUMN feature_schema_fp SET NOT NULL,
    ALTER COLUMN scoring_schema_fp SET NOT NULL,
    ALTER COLUMN aggregated_flags SET DEFAULT 0,
    ALTER COLUMN aggregated_flags SET NOT NULL,
    ALTER COLUMN delta_clamped SET DEFAULT FALSE,
    ALTER COLUMN delta_clamped SET NOT NULL,
    ALTER COLUMN inserted_at SET DEFAULT now(),
    ALTER COLUMN inserted_at SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'agent_scores_score_range'
    ) THEN
        ALTER TABLE agent_scores
            ADD CONSTRAINT agent_scores_score_range
            CHECK (score >= 0 AND score <= 1000);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'agent_scores_confidence_range'
    ) THEN
        ALTER TABLE agent_scores
            ADD CONSTRAINT agent_scores_confidence_range
            CHECK (confidence >= 0 AND confidence <= 1000);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'agent_scores_alert_tier'
    ) THEN
        ALTER TABLE agent_scores
            ADD CONSTRAINT agent_scores_alert_tier
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
END $$;

-- Latest-score lookups: most reads ask "what is agent X's current score".
DO $$
BEGIN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_agent_scores_wallet_time
             ON agent_scores (agent_wallet, computed_at DESC)';
END $$;

-- Alerting / dashboards scan by tier.
DO $$
BEGIN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_agent_scores_alert
             ON agent_scores (alert_tier, computed_at DESC)';
END $$;

COMMENT ON TABLE agent_scores IS
    'Append-only composite trust scores (Scorer v2, Day 13). Latest row per agent_wallet is current.';
COMMENT ON COLUMN agent_scores.score IS
    'Composite 0-1000 score AFTER the 200-point delta guard rail.';
COMMENT ON COLUMN agent_scores.confidence IS
    'Data-sufficiency confidence 0-1000; low for new/sparse agents.';
COMMENT ON COLUMN agent_scores.gaming_flag IS
    'True if behavioural entropy collapsed >25% vs baseline (score-gaming signal).';
