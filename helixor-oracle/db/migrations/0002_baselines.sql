-- =============================================================================
-- Migration 0002 — Add agent_baselines table.
--
-- Stores the most recent computed baseline per agent + a history table for
-- baseline evolution (used by anomaly detection in V2).
-- =============================================================================

INSERT INTO schema_version (version, description) VALUES
    (2, 'Add agent_baselines + agent_baseline_history')
ON CONFLICT (version) DO NOTHING;

-- ── Current baseline ────────────────────────────────────────────────────────
-- One row per agent. Overwritten on each recompute.
CREATE TABLE IF NOT EXISTS agent_baselines (
    agent_wallet         TEXT PRIMARY KEY REFERENCES registered_agents(agent_wallet),

    -- Three signals (the entire scoring contract)
    success_rate         NUMERIC(8,6) NOT NULL,           -- 0.000000 to 1.000000
    median_daily_tx      INTEGER      NOT NULL,           -- median tx count per active day
    sol_volatility_mad   BIGINT       NOT NULL,           -- median absolute deviation, lamports

    -- Metadata
    tx_count             INTEGER      NOT NULL,           -- transactions used
    active_days          INTEGER      NOT NULL,           -- days with at least 1 tx
    window_start         TIMESTAMPTZ  NOT NULL,
    window_end           TIMESTAMPTZ  NOT NULL,
    window_days          INTEGER      NOT NULL,

    -- For on-chain commitment + change detection
    baseline_hash        TEXT NOT NULL,                   -- hex SHA-256 over canonical signals

    -- Timestamps
    computed_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    valid_until          TIMESTAMPTZ  NOT NULL,           -- recompute after this

    -- Schema version for the baseline algorithm itself.
    -- If we change how signals are computed, bump this so consumers know.
    algo_version         INTEGER      NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_baselines_valid_until ON agent_baselines (valid_until);

-- ── Baseline history (append-only) ──────────────────────────────────────────
-- Each recompute appends a row. Used by anomaly detection to spot drift
-- in baselines over time (e.g. agent's success_rate has slowly degraded
-- over 6 months — that's a different signal than acute failure).
CREATE TABLE IF NOT EXISTS agent_baseline_history (
    id                   BIGSERIAL PRIMARY KEY,
    agent_wallet         TEXT NOT NULL REFERENCES registered_agents(agent_wallet),
    success_rate         NUMERIC(8,6) NOT NULL,
    median_daily_tx      INTEGER      NOT NULL,
    sol_volatility_mad   BIGINT       NOT NULL,
    tx_count             INTEGER      NOT NULL,
    active_days          INTEGER      NOT NULL,
    baseline_hash        TEXT         NOT NULL,
    algo_version         INTEGER      NOT NULL,
    computed_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    window_start         TIMESTAMPTZ  NOT NULL,
    window_end           TIMESTAMPTZ  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_baseline_hist_agent_time
    ON agent_baseline_history (agent_wallet, computed_at DESC);

COMMENT ON TABLE agent_baselines IS
    'Current baseline per agent. Recomputed on a schedule or on-demand.';
COMMENT ON TABLE agent_baseline_history IS
    'Append-only history of all baseline computations. Never deleted.';
