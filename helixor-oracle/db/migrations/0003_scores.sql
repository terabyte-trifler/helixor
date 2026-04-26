-- =============================================================================
-- Migration 0003 — Score storage.
--
-- Stores the most recent score per agent + an immutable history of every
-- score ever computed. Day 7 will sync the current row on-chain.
-- =============================================================================

INSERT INTO schema_version (version, description) VALUES
    (3, 'Add agent_scores + agent_score_history')
ON CONFLICT (version) DO NOTHING;

-- ── Current score (one row per agent) ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_scores (
    agent_wallet         TEXT PRIMARY KEY REFERENCES registered_agents(agent_wallet),

    -- The single number that matters
    score                INTEGER NOT NULL CHECK (score BETWEEN 0 AND 1000),
    alert                TEXT    NOT NULL CHECK (alert IN ('GREEN','YELLOW','RED')),

    -- Component breakdown for debugging + transparency
    success_rate_score   INTEGER NOT NULL CHECK (success_rate_score BETWEEN 0 AND 500),
    consistency_score    INTEGER NOT NULL CHECK (consistency_score  BETWEEN 0 AND 300),
    stability_score      INTEGER NOT NULL CHECK (stability_score    BETWEEN 0 AND 200),

    -- Pre-clamp value for forensics (could differ from `score` if guard rail fired)
    raw_score            INTEGER NOT NULL,
    guard_rail_applied   BOOLEAN NOT NULL DEFAULT FALSE,

    -- The window stats this score was computed from
    window_success_rate  NUMERIC(8,6) NOT NULL,
    window_tx_count      INTEGER      NOT NULL,
    window_sol_volatility BIGINT      NOT NULL,

    -- The baseline this score was scored against
    baseline_hash        TEXT NOT NULL,
    baseline_algo_version INTEGER NOT NULL,

    -- Anomaly flag — set when window deviates strongly from baseline
    anomaly_flag         BOOLEAN NOT NULL DEFAULT FALSE,

    -- Versioning
    scoring_algo_version INTEGER NOT NULL,
    weights_version      INTEGER NOT NULL,

    -- Timestamps
    computed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    written_onchain_at   TIMESTAMPTZ                                  -- set by Day 7
);

CREATE INDEX IF NOT EXISTS idx_scores_alert         ON agent_scores (alert);
CREATE INDEX IF NOT EXISTS idx_scores_computed_at   ON agent_scores (computed_at DESC);
CREATE INDEX IF NOT EXISTS idx_scores_unsynced
    ON agent_scores (computed_at)
    WHERE written_onchain_at IS NULL;

COMMENT ON TABLE agent_scores IS
    'Current trust score per agent. Updated each scoring epoch.';


-- ── Score history (append-only, immutable) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_score_history (
    id                   BIGSERIAL PRIMARY KEY,
    agent_wallet         TEXT NOT NULL REFERENCES registered_agents(agent_wallet),

    score                INTEGER NOT NULL,
    alert                TEXT    NOT NULL,

    success_rate_score   INTEGER NOT NULL,
    consistency_score    INTEGER NOT NULL,
    stability_score      INTEGER NOT NULL,
    raw_score            INTEGER NOT NULL,
    guard_rail_applied   BOOLEAN NOT NULL,

    window_success_rate  NUMERIC(8,6) NOT NULL,
    window_tx_count      INTEGER      NOT NULL,
    window_sol_volatility BIGINT      NOT NULL,

    baseline_hash        TEXT NOT NULL,
    baseline_algo_version INTEGER NOT NULL,

    anomaly_flag         BOOLEAN NOT NULL,
    scoring_algo_version INTEGER NOT NULL,
    weights_version      INTEGER NOT NULL,

    computed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Optional CPI tx signature when this score was written on-chain
    onchain_tx_signature TEXT
);

CREATE INDEX IF NOT EXISTS idx_score_hist_agent_time
    ON agent_score_history (agent_wallet, computed_at DESC);

COMMENT ON TABLE agent_score_history IS
    'Append-only log of every score ever computed. Never deleted.';


-- ── Diagnostic view: agents needing first score ─────────────────────────────
CREATE OR REPLACE VIEW agents_pending_score AS
SELECT ra.agent_wallet, ab.computed_at AS baseline_computed_at
FROM registered_agents ra
JOIN agent_baselines    ab ON ab.agent_wallet = ra.agent_wallet
LEFT JOIN agent_scores  sc ON sc.agent_wallet = ra.agent_wallet
WHERE ra.active = TRUE
  AND sc.agent_wallet IS NULL
ORDER BY ab.computed_at ASC;
