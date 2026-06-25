-- =============================================================================
-- Migration 0007 — Baseline Engine v3.
--
-- Day 6 adds `daily_success_rate_series` to BaselineStats. This is the
-- chronological per-active-day success rate sequence consumed by the drift
-- detectors that operate on a sequential stream (CUSUM, ADWIN, DDM).
--
-- The new field is part of the committed `stats_hash` payload, so this is
-- a BASELINE_ALGO_VERSION bump (2 → 3). Existing v2 baselines remain
-- readable but are flagged incompatible by the engine; the backfill job
-- picks them up on its next run.
-- =============================================================================

INSERT INTO schema_version (version, description) VALUES
    (7, 'Baseline Engine v3: daily_success_rate_series for sequential drift detectors')
ON CONFLICT (version) DO NOTHING;


-- ── agent_baselines — add the v3 column ─────────────────────────────────────

ALTER TABLE agent_baselines
    ADD COLUMN IF NOT EXISTS daily_success_rate_series DOUBLE PRECISION[];

ALTER TABLE agent_baseline_history
    ADD COLUMN IF NOT EXISTS daily_success_rate_series DOUBLE PRECISION[];

-- Each value in the series is a fraction in [0, 1]. Postgres can't enforce
-- per-element CHECK constraints on arrays directly, so this is enforced at
-- the Python construction boundary (BaselineStats.__post_init__).

COMMENT ON COLUMN agent_baselines.daily_success_rate_series IS
    'Per-active-day success rate, chronological order. Length = days_with_activity. Consumed by CUSUM/ADWIN/DDM drift detectors (Day 6).';
