-- =============================================================================
-- Migration 0005 — Monitoring + alert deduplication.
--
-- New tables:
--   monitoring_alerts       — every alert fired (audit trail)
--   monitoring_alert_state  — current state per alert key (for cooldown logic)
--   monitoring_slo_samples  — per-check measurements for SLO computation
--   monitored_agents        — designated "real" agents tracked specifically
-- =============================================================================

INSERT INTO schema_version (version, description) VALUES
    (5, 'Add monitoring + alert dedup + SLO tracking')
ON CONFLICT (version) DO NOTHING;


-- ── Alert audit trail (every alert ever fired, never deleted) ───────────────
CREATE TABLE IF NOT EXISTS monitoring_alerts (
    id               BIGSERIAL PRIMARY KEY,
    alert_key        TEXT      NOT NULL,
    severity         TEXT      NOT NULL CHECK (severity IN ('info','warning','critical')),
    title            TEXT      NOT NULL,
    body             TEXT      NOT NULL,
    context          JSONB     NOT NULL DEFAULT '{}'::jsonb,
    delivered_to     TEXT[]    NOT NULL DEFAULT '{}',
    fired_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    check_run_id     TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_fired_at ON monitoring_alerts (fired_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_key      ON monitoring_alerts (alert_key, fired_at DESC);


-- ── Per-key alert state (so we don't spam) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS monitoring_alert_state (
    alert_key        TEXT PRIMARY KEY,
    is_active        BOOLEAN     NOT NULL DEFAULT TRUE,
    severity         TEXT        NOT NULL,
    first_fired_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_fired_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    fire_count       INTEGER     NOT NULL DEFAULT 1,
    last_notified_at TIMESTAMPTZ,
    resolved_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_alert_state_active ON monitoring_alert_state (is_active);


-- ── SLO samples (every check writes one row) ────────────────────────────────
CREATE TABLE IF NOT EXISTS monitoring_slo_samples (
    id               BIGSERIAL PRIMARY KEY,
    check_name       TEXT      NOT NULL,
    value_ms         BIGINT,
    value_text       TEXT,
    healthy          BOOLEAN   NOT NULL,
    context          JSONB     NOT NULL DEFAULT '{}'::jsonb,
    sampled_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_slo_check_time
    ON monitoring_slo_samples (check_name, sampled_at DESC);
CREATE INDEX IF NOT EXISTS idx_slo_healthy
    ON monitoring_slo_samples (healthy, sampled_at DESC);


-- ── Designated monitored agents ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS monitored_agents (
    agent_wallet         TEXT PRIMARY KEY REFERENCES registered_agents(agent_wallet),
    label                TEXT NOT NULL,
    expected_min_score   INTEGER,
    expected_alert_level TEXT,
    monitor_started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    enabled              BOOLEAN NOT NULL DEFAULT TRUE,
    notes                TEXT
);
CREATE INDEX IF NOT EXISTS idx_monitored_enabled ON monitored_agents (enabled);

COMMENT ON TABLE monitored_agents IS
    'Day 11: agents we explicitly track for the "real agent running continuously" success criterion.';
