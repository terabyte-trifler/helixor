-- =============================================================================
-- Migration 0006 — Baseline Engine v2.
--
-- The MVP's agent_baselines stored 3 scalar signals. V2 stores:
--   - feature_means  float[100]   per-feature mean over the daily-vector series
--   - feature_stds   float[100]   per-feature population stddev
--   - stats_hash     text         the canonical SHA-256 commitment (-> on-chain)
--   - feature_schema_version int  so a schema mismatch is detectable at read time
--   plus scalar summaries + data-sufficiency metadata.
--
-- agent_baseline_history is APPEND-ONLY: every baseline ever computed.
-- agent_baselines is the latest-per-agent view (upserted).
--
-- This migration is written to be safe on a database that already has the
-- MVP's agent_baselines / agent_baseline_history tables: it ADDs columns
-- rather than dropping, and backfills NULLs to safe defaults. Old MVP
-- baselines remain readable but will have baseline_algo_version = 1 and a
-- NULL stats_hash, so list_agents_needing_v2_baseline() picks them up.
-- =============================================================================

INSERT INTO schema_version (version, description) VALUES
    (6, 'Baseline Engine v2: 100-feature means/stds + stats_hash commitment')
ON CONFLICT (version) DO NOTHING;


-- ── agent_baselines — latest baseline per agent ─────────────────────────────
-- Add the v2 columns. IF NOT EXISTS makes the migration idempotent.

ALTER TABLE agent_baselines
    ADD COLUMN IF NOT EXISTS baseline_algo_version      INTEGER,
    ADD COLUMN IF NOT EXISTS feature_schema_version     INTEGER,
    ADD COLUMN IF NOT EXISTS feature_schema_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS feature_means              DOUBLE PRECISION[],
    ADD COLUMN IF NOT EXISTS feature_stds               DOUBLE PRECISION[],
    ADD COLUMN IF NOT EXISTS txtype_distribution        DOUBLE PRECISION[],
    ADD COLUMN IF NOT EXISTS action_entropy             DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS success_rate_30d           DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS transaction_count          INTEGER,
    ADD COLUMN IF NOT EXISTS days_with_activity         INTEGER,
    ADD COLUMN IF NOT EXISTS is_provisional             BOOLEAN,
    ADD COLUMN IF NOT EXISTS stats_hash                 TEXT,
    ADD COLUMN IF NOT EXISTS computed_at                TIMESTAMPTZ;

-- V2 rows no longer populate the old MVP scalar columns. Keep those columns
-- for backwards compatibility, but make them nullable so v1 and v2 rows can
-- coexist in the same tables during rollout.
ALTER TABLE agent_baselines
    ALTER COLUMN success_rate       DROP NOT NULL,
    ALTER COLUMN median_daily_tx    DROP NOT NULL,
    ALTER COLUMN sol_volatility_mad DROP NOT NULL,
    ALTER COLUMN tx_count           DROP NOT NULL,
    ALTER COLUMN active_days        DROP NOT NULL,
    ALTER COLUMN window_days        DROP NOT NULL,
    ALTER COLUMN baseline_hash      DROP NOT NULL,
    ALTER COLUMN valid_until        DROP NOT NULL,
    ALTER COLUMN algo_version       DROP NOT NULL;

-- Any pre-existing MVP rows: tag them as algo v1 so the backfill finds them.
UPDATE agent_baselines
    SET baseline_algo_version = 1
    WHERE baseline_algo_version IS NULL;

-- ── Array-length contract ───────────────────────────────────────────────────
-- A 100-element vector stored as an unbounded float[] will, eventually, get a
-- 99-element row from some bug. These CHECK constraints make that impossible.
-- NOT VALID + a separate VALIDATE keeps the migration fast on a big table and
-- lets it run even if a few legacy rows are non-conforming (they'll be
-- replaced by the backfill).

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'agent_baselines_means_len'
    ) THEN
        ALTER TABLE agent_baselines
            ADD CONSTRAINT agent_baselines_means_len
            CHECK (feature_means IS NULL OR array_length(feature_means, 1) = 100)
            NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'agent_baselines_stds_len'
    ) THEN
        ALTER TABLE agent_baselines
            ADD CONSTRAINT agent_baselines_stds_len
            CHECK (feature_stds IS NULL OR array_length(feature_stds, 1) = 100)
            NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'agent_baselines_txtype_len'
    ) THEN
        ALTER TABLE agent_baselines
            ADD CONSTRAINT agent_baselines_txtype_len
            CHECK (txtype_distribution IS NULL OR array_length(txtype_distribution, 1) = 5)
            NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'agent_baselines_hash_len'
    ) THEN
        ALTER TABLE agent_baselines
            ADD CONSTRAINT agent_baselines_hash_len
            CHECK (stats_hash IS NULL OR char_length(stats_hash) = 64)
            NOT VALID;
    END IF;
END $$;


-- ── agent_baseline_history — APPEND-ONLY audit trail ────────────────────────
-- Create the table if the MVP didn't have it; add v2 columns if it did.

CREATE TABLE IF NOT EXISTS agent_baseline_history (
    id                          BIGSERIAL PRIMARY KEY,
    agent_wallet                TEXT NOT NULL,
    baseline_algo_version       INTEGER NOT NULL,
    feature_schema_version      INTEGER,
    feature_schema_fingerprint  TEXT,
    window_start                TIMESTAMPTZ NOT NULL,
    window_end                  TIMESTAMPTZ NOT NULL,
    feature_means               DOUBLE PRECISION[],
    feature_stds                DOUBLE PRECISION[],
    txtype_distribution         DOUBLE PRECISION[],
    action_entropy              DOUBLE PRECISION,
    success_rate_30d            DOUBLE PRECISION,
    transaction_count           INTEGER,
    days_with_activity          INTEGER,
    is_provisional              BOOLEAN,
    computed_at                 TIMESTAMPTZ NOT NULL,
    stats_hash                  TEXT,
    -- append-only de-dup key: re-running the SAME computation is idempotent
    CONSTRAINT agent_baseline_history_dedup
        UNIQUE (agent_wallet, stats_hash, window_end)
);

-- If the table pre-existed from the MVP, add any missing v2 columns.
ALTER TABLE agent_baseline_history
    ADD COLUMN IF NOT EXISTS baseline_algo_version      INTEGER,
    ADD COLUMN IF NOT EXISTS feature_schema_version     INTEGER,
    ADD COLUMN IF NOT EXISTS feature_schema_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS feature_means              DOUBLE PRECISION[],
    ADD COLUMN IF NOT EXISTS feature_stds               DOUBLE PRECISION[],
    ADD COLUMN IF NOT EXISTS txtype_distribution        DOUBLE PRECISION[],
    ADD COLUMN IF NOT EXISTS action_entropy             DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS success_rate_30d           DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS transaction_count          INTEGER,
    ADD COLUMN IF NOT EXISTS days_with_activity         INTEGER,
    ADD COLUMN IF NOT EXISTS is_provisional             BOOLEAN,
    ADD COLUMN IF NOT EXISTS stats_hash                 TEXT;

ALTER TABLE agent_baseline_history
    ALTER COLUMN success_rate       DROP NOT NULL,
    ALTER COLUMN median_daily_tx    DROP NOT NULL,
    ALTER COLUMN sol_volatility_mad DROP NOT NULL,
    ALTER COLUMN tx_count           DROP NOT NULL,
    ALTER COLUMN active_days        DROP NOT NULL,
    ALTER COLUMN baseline_hash      DROP NOT NULL,
    ALTER COLUMN algo_version       DROP NOT NULL;

UPDATE agent_baseline_history
    SET baseline_algo_version = COALESCE(baseline_algo_version, algo_version, 1)
    WHERE baseline_algo_version IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'agent_baseline_history_dedup'
    ) THEN
        ALTER TABLE agent_baseline_history
            ADD CONSTRAINT agent_baseline_history_dedup
            UNIQUE (agent_wallet, stats_hash, window_end);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_baseline_history_agent_time
    ON agent_baseline_history (agent_wallet, computed_at DESC);

CREATE INDEX IF NOT EXISTS idx_baseline_history_algo
    ON agent_baseline_history (baseline_algo_version);


-- ── Append-only enforcement ─────────────────────────────────────────────────
-- agent_baseline_history must NEVER be updated or deleted. A trigger turns any
-- such attempt into an error — the audit trail is immutable by construction,
-- not just by convention.

CREATE OR REPLACE FUNCTION reject_baseline_history_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'agent_baseline_history is append-only; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_baseline_history_no_update ON agent_baseline_history;
CREATE TRIGGER trg_baseline_history_no_update
    BEFORE UPDATE OR DELETE ON agent_baseline_history
    FOR EACH ROW EXECUTE FUNCTION reject_baseline_history_mutation();


-- ── Index for the backfill worklist query ───────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_baselines_algo_schema
    ON agent_baselines (baseline_algo_version, feature_schema_fingerprint);


COMMENT ON TABLE  agent_baseline_history IS
    'Append-only audit trail of every baseline ever computed. Immutable (trigger-enforced).';
COMMENT ON COLUMN agent_baselines.stats_hash IS
    'Canonical SHA-256 commitment over statistical content. This is the value committed on-chain (Day 3).';
COMMENT ON COLUMN agent_baselines.feature_schema_fingerprint IS
    'sha256 of the ordered 100 feature names. A mismatch means the baseline is incompatible with the current engine.';
