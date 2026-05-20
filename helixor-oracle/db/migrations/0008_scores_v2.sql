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
    id                      BIGSERIAL    PRIMARY KEY,
    agent_wallet            TEXT         NOT NULL,

    -- The user-facing composite score, 0..1000, AFTER the delta guard rail.
    score                   INTEGER      NOT NULL,
    alert_tier              TEXT         NOT NULL,   -- 'GREEN' | 'YELLOW' | 'RED'

    -- Per-dimension contributions to the (pre-rail) aggregate.
    --   dim1 = drift, dim2 = anomaly, dim3 = performance,
    --   dim4 = consistency, dim5 = security
    dim1                    INTEGER      NOT NULL,
    dim2                    INTEGER      NOT NULL,
    dim3                    INTEGER      NOT NULL,
    dim4                    INTEGER      NOT NULL,
    dim5                    INTEGER      NOT NULL,

    -- Day-13 additions.
    confidence              INTEGER      NOT NULL,   -- 0..1000 data sufficiency
    gaming_flag             BOOLEAN      NOT NULL,   -- behavioural-entropy collapse
    scoring_algo_version    INTEGER      NOT NULL,

    -- Provenance — links the score to the exact inputs that produced it.
    baseline_stats_hash     TEXT         NOT NULL,
    feature_schema_fp       TEXT         NOT NULL,
    scoring_schema_fp       TEXT         NOT NULL,
    aggregated_flags        BIGINT       NOT NULL DEFAULT 0,
    delta_clamped           BOOLEAN      NOT NULL DEFAULT FALSE,

    computed_at             TIMESTAMPTZ  NOT NULL,
    inserted_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- Range guards — the same invariants the Python ScoreResult enforces.
    CONSTRAINT agent_scores_score_range
        CHECK (score >= 0 AND score <= 1000),
    CONSTRAINT agent_scores_confidence_range
        CHECK (confidence >= 0 AND confidence <= 1000),
    CONSTRAINT agent_scores_alert_tier
        CHECK (alert_tier IN ('GREEN', 'YELLOW', 'RED')),
    CONSTRAINT agent_scores_dims_nonneg
        CHECK (dim1 >= 0 AND dim2 >= 0 AND dim3 >= 0
               AND dim4 >= 0 AND dim5 >= 0)
);

-- If migration 0003 already created the MVP current-score table, the
-- CREATE TABLE IF NOT EXISTS above is a no-op. Add the V2 columns explicitly
-- so a fresh replay of 0001..0008 leaves the table compatible with both the
-- older API code (`alert`, success/consistency/stability columns) and the V2
-- scorer metadata.
ALTER TABLE agent_scores
    ADD COLUMN IF NOT EXISTS alert_tier           TEXT,
    ADD COLUMN IF NOT EXISTS dim1                 INTEGER,
    ADD COLUMN IF NOT EXISTS dim2                 INTEGER,
    ADD COLUMN IF NOT EXISTS dim3                 INTEGER,
    ADD COLUMN IF NOT EXISTS dim4                 INTEGER,
    ADD COLUMN IF NOT EXISTS dim5                 INTEGER,
    ADD COLUMN IF NOT EXISTS confidence           INTEGER,
    ADD COLUMN IF NOT EXISTS gaming_flag          BOOLEAN,
    ADD COLUMN IF NOT EXISTS baseline_stats_hash  TEXT,
    ADD COLUMN IF NOT EXISTS feature_schema_fp    TEXT,
    ADD COLUMN IF NOT EXISTS scoring_schema_fp    TEXT,
    ADD COLUMN IF NOT EXISTS aggregated_flags     BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS delta_clamped        BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS inserted_at          TIMESTAMPTZ DEFAULT now();

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'agent_scores'
          AND column_name = 'alert'
    ) THEN
        UPDATE agent_scores
            SET alert_tier = COALESCE(alert_tier, alert)
            WHERE alert_tier IS NULL;
    END IF;
END $$;

-- Latest-score lookups: most reads ask "what is agent X's current score".
CREATE INDEX IF NOT EXISTS idx_agent_scores_wallet_time
    ON agent_scores (agent_wallet, computed_at DESC);

-- Alerting / dashboards scan by tier.
CREATE INDEX IF NOT EXISTS idx_agent_scores_alert
    ON agent_scores (alert_tier, computed_at DESC);

COMMENT ON TABLE agent_scores IS
    'Append-only composite trust scores (Scorer v2, Day 13). Latest row per agent_wallet is current.';
COMMENT ON COLUMN agent_scores.score IS
    'Composite 0-1000 score AFTER the 200-point delta guard rail.';
COMMENT ON COLUMN agent_scores.confidence IS
    'Data-sufficiency confidence 0-1000; low for new/sparse agents.';
COMMENT ON COLUMN agent_scores.gaming_flag IS
    'True if behavioural entropy collapsed >25% vs baseline (score-gaming signal).';
