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


-- ── agent_scores — v2 columns on top of the legacy current-score table ──────
--
-- Migration 0003 already created `agent_scores` as the current-row table used
-- by the API and Day-7 sync hooks. This migration must therefore ALTER the
-- table in place rather than using CREATE TABLE IF NOT EXISTS, which would be
-- a no-op on upgraded databases and leave v2 columns missing.

ALTER TABLE agent_scores
    ADD COLUMN IF NOT EXISTS alert_tier          TEXT,
    ADD COLUMN IF NOT EXISTS dim1                INTEGER,
    ADD COLUMN IF NOT EXISTS dim2                INTEGER,
    ADD COLUMN IF NOT EXISTS dim3                INTEGER,
    ADD COLUMN IF NOT EXISTS dim4                INTEGER,
    ADD COLUMN IF NOT EXISTS dim5                INTEGER,
    ADD COLUMN IF NOT EXISTS confidence          INTEGER,
    ADD COLUMN IF NOT EXISTS gaming_flag         BOOLEAN,
    ADD COLUMN IF NOT EXISTS baseline_stats_hash TEXT,
    ADD COLUMN IF NOT EXISTS feature_schema_fp   TEXT,
    ADD COLUMN IF NOT EXISTS scoring_schema_fp   TEXT,
    ADD COLUMN IF NOT EXISTS aggregated_flags    BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS delta_clamped       BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS inserted_at         TIMESTAMPTZ DEFAULT now();

DO $$
BEGIN
    EXECUTE 'UPDATE agent_scores
             SET alert_tier = COALESCE(alert_tier, alert),
                 dim1 = COALESCE(dim1, success_rate_score),
                 dim2 = COALESCE(dim2, 0),
                 dim3 = COALESCE(dim3, stability_score),
                 dim4 = COALESCE(dim4, consistency_score),
                 dim5 = COALESCE(dim5, 0),
                 confidence = COALESCE(confidence, 1000),
                 gaming_flag = COALESCE(gaming_flag, FALSE),
                 baseline_stats_hash = COALESCE(baseline_stats_hash, baseline_hash),
                 feature_schema_fp = COALESCE(feature_schema_fp, ''''),
                 scoring_schema_fp = COALESCE(scoring_schema_fp, ''''),
                 aggregated_flags = COALESCE(aggregated_flags, 0),
                 delta_clamped = COALESCE(delta_clamped, guard_rail_applied),
                 inserted_at = COALESCE(inserted_at, computed_at)';
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
DO $$
BEGIN
    EXECUTE 'COMMENT ON COLUMN agent_scores.score IS
             ''Composite 0-1000 score AFTER the 200-point delta guard rail.''';
    EXECUTE 'COMMENT ON COLUMN agent_scores.confidence IS
             ''Data-sufficiency confidence 0-1000; low for new/sparse agents.''';
    EXECUTE 'COMMENT ON COLUMN agent_scores.gaming_flag IS
             ''True if behavioural entropy collapsed >25% vs baseline (score-gaming signal).''';
END $$;
