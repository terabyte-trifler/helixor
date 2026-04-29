-- =============================================================================
-- Migration 0006 — Operator integration tracking.
--
-- Day 12 success criterion: ONE real operator confirms their agent is
-- using the plugin in production.
-- =============================================================================

INSERT INTO schema_version (version, description) VALUES
    (6, 'Add operators + plugin_telemetry')
ON CONFLICT (version) DO NOTHING;


CREATE TABLE IF NOT EXISTS operators (
    id                BIGSERIAL PRIMARY KEY,
    api_key_hash      TEXT UNIQUE,
    api_key_prefix    TEXT,
    contact_email     TEXT,
    discord_handle    TEXT,
    organization      TEXT,
    notes             TEXT,
    tier              TEXT NOT NULL DEFAULT 'free' CHECK (tier IN ('free','partner','team')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at      TIMESTAMPTZ,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_operators_api_key_hash ON operators (api_key_hash);
CREATE INDEX IF NOT EXISTS idx_operators_last_seen    ON operators (last_seen_at DESC);

COMMENT ON TABLE operators IS
    'Registered Helixor partners. API key is optional — plugin works anonymously.';


CREATE TABLE IF NOT EXISTS plugin_telemetry (
    id                BIGSERIAL PRIMARY KEY,
    operator_id       BIGINT REFERENCES operators(id) ON DELETE SET NULL,
    event_type        TEXT NOT NULL CHECK (event_type IN (
        'plugin_initialized',
        'agent_score_fetched',
        'action_allowed',
        'action_blocked',
        'gate_error',
        'score_changed',
        'anomaly_detected',
        'agent_deactivated',
        'plugin_shutdown'
    )),
    plugin_version    TEXT NOT NULL,
    elizaos_version   TEXT,
    node_version      TEXT,
    agent_wallet      TEXT,
    character_name    TEXT,
    score             INTEGER,
    alert_level       TEXT,
    block_reason      TEXT,
    action_name       TEXT,
    error_message     TEXT,
    extra             JSONB DEFAULT '{}'::jsonb,
    source_ip         INET,
    user_agent        TEXT,
    beacon_id         TEXT NOT NULL,
    received_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_telemetry_operator_time
    ON plugin_telemetry (operator_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_event_time
    ON plugin_telemetry (event_type, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_agent_time
    ON plugin_telemetry (agent_wallet, received_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_telemetry_beacon_dedup
    ON plugin_telemetry (beacon_id);

COMMENT ON TABLE plugin_telemetry IS
    'Plugin lifecycle + decision telemetry. METADATA-ONLY — never message content.';


CREATE TABLE IF NOT EXISTS operator_integrations (
    operator_id        BIGINT REFERENCES operators(id) ON DELETE CASCADE,
    agent_wallet       TEXT NOT NULL,
    character_name     TEXT,
    plugin_version     TEXT,
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    blocks_count       INTEGER NOT NULL DEFAULT 0,
    allows_count       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (operator_id, agent_wallet)
);
CREATE INDEX IF NOT EXISTS idx_integrations_agent
    ON operator_integrations (agent_wallet);
CREATE INDEX IF NOT EXISTS idx_integrations_recent
    ON operator_integrations (last_seen_at DESC);
