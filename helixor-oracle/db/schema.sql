-- =============================================================================
-- Helixor Oracle — Database Schema
--
-- Plain PostgreSQL 16+. No TimescaleDB extension required for MVP.
-- Tested with PostgreSQL 16.4.
--
-- Migration strategy: this is the initial schema. Future migrations live in
-- db/migrations/NNNN_description.sql, applied by db/migrate.py.
-- =============================================================================

-- ── Schema metadata ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS schema_version (
    version      INTEGER PRIMARY KEY,
    description  TEXT NOT NULL,
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO schema_version (version, description) VALUES
    (1, 'Initial schema — registered_agents + agent_transactions + webhook_subscriptions')
ON CONFLICT (version) DO NOTHING;

-- ── Registered agents ────────────────────────────────────────────────────────
-- Source of truth: on-chain AgentRegistration PDAs. Synced by agent_sync.py
-- via the AgentRegistered event listener.
--
-- We keep this as a denormalized cache so the webhook receiver can do a
-- fast indexed lookup without an RPC call per transaction.
CREATE TABLE IF NOT EXISTS registered_agents (
    agent_wallet         TEXT PRIMARY KEY,
    owner_wallet         TEXT NOT NULL,
    name                 TEXT,                                  -- from AgentRegistered.name
    registration_pda     TEXT NOT NULL,                         -- the PDA address
    registered_at        TIMESTAMPTZ NOT NULL,                  -- on-chain block time
    active               BOOLEAN NOT NULL DEFAULT TRUE,
    onchain_signature    TEXT NOT NULL UNIQUE,                  -- registration tx sig

    -- Webhook lifecycle
    helius_webhook_id    TEXT,                                  -- NULL until registered
    webhook_registered_at TIMESTAMPTZ,
    webhook_failures     INTEGER NOT NULL DEFAULT 0,            -- consecutive failures

    -- Timestamps
    synced_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),    -- when we saw the event
    deactivated_at       TIMESTAMPTZ                            -- when active flipped false
);

CREATE INDEX IF NOT EXISTS idx_agents_active     ON registered_agents (active) WHERE active = TRUE;
CREATE INDEX IF NOT EXISTS idx_agents_registered ON registered_agents (registered_at DESC);

COMMENT ON TABLE registered_agents IS
    'Local cache of on-chain AgentRegistration PDAs. Synced by agent_sync.py.';

-- ── Webhook subscriptions tracking ───────────────────────────────────────────
-- Records every Helius webhook we have ever registered, including failures.
-- Used by the reconciler to detect drift between Helius's view and ours.
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id                BIGSERIAL PRIMARY KEY,
    agent_wallet      TEXT NOT NULL REFERENCES registered_agents(agent_wallet) ON DELETE CASCADE,
    helius_webhook_id TEXT,
    state             TEXT NOT NULL CHECK (state IN ('pending','active','failed','removed')),
    error_message     TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhooks_agent ON webhook_subscriptions (agent_wallet);
CREATE INDEX IF NOT EXISTS idx_webhooks_state ON webhook_subscriptions (state);

-- ── Agent transactions ───────────────────────────────────────────────────────
-- Every transaction observed for a registered agent. Append-only, never
-- updated. The scoring engine reads this table to compute baseline + signals.
--
-- Foreign key to registered_agents is intentional: orphan transactions are
-- a bug. But we don't ON DELETE CASCADE — if an agent is deregistered we
-- want their tx history retained for forensics.
CREATE TABLE IF NOT EXISTS agent_transactions (
    id              BIGSERIAL PRIMARY KEY,
    agent_wallet    TEXT NOT NULL REFERENCES registered_agents(agent_wallet),
    tx_signature    TEXT NOT NULL UNIQUE,
    slot            BIGINT NOT NULL,
    block_time      TIMESTAMPTZ NOT NULL,
    success         BOOLEAN NOT NULL,
    program_ids     TEXT[] NOT NULL DEFAULT '{}',
    sol_change      BIGINT NOT NULL DEFAULT 0,
    fee             BIGINT NOT NULL DEFAULT 0,
    raw_meta        JSONB NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source          TEXT NOT NULL DEFAULT 'webhook'             -- webhook | backfill | replay | e2e_seed
        CHECK (source IN ('webhook','backfill','replay','e2e_seed'))
);

-- Primary read pattern: "give me last 7 days for agent X ordered by time DESC"
CREATE INDEX IF NOT EXISTS idx_tx_agent_time ON agent_transactions (agent_wallet, block_time DESC);

-- Secondary: "what did all agents do in the last hour?" (for monitoring)
CREATE INDEX IF NOT EXISTS idx_tx_recent     ON agent_transactions (block_time DESC);

-- For idempotency on webhook retries
CREATE UNIQUE INDEX IF NOT EXISTS idx_tx_sig  ON agent_transactions (tx_signature);

-- For monitoring webhook drops vs RPC backfill
CREATE INDEX IF NOT EXISTS idx_tx_source     ON agent_transactions (source) WHERE source != 'webhook';

COMMENT ON TABLE agent_transactions IS
    'Append-only ledger of every transaction by registered agents.';

-- ── Webhook event audit log ──────────────────────────────────────────────────
-- Records every webhook POST received, regardless of whether it produced
-- a database row. Used to debug "why was tx X dropped?".
CREATE TABLE IF NOT EXISTS webhook_events (
    id              BIGSERIAL PRIMARY KEY,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_id      TEXT NOT NULL,                              -- for log correlation
    tx_count        INTEGER NOT NULL,
    inserted_count  INTEGER NOT NULL,
    skipped_count   INTEGER NOT NULL,                           -- duplicates or unknown agents
    error           TEXT,                                       -- non-null = handler failed
    duration_ms     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_webhook_events_time ON webhook_events (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_events_err  ON webhook_events (error) WHERE error IS NOT NULL;

-- ── Helper view: agents needing webhooks ─────────────────────────────────────
CREATE OR REPLACE VIEW agents_pending_webhook AS
SELECT agent_wallet, owner_wallet, registration_pda, registered_at
FROM registered_agents
WHERE active = TRUE
  AND helius_webhook_id IS NULL
ORDER BY registered_at;
