-- =============================================================================
-- Migration 0009 — TimescaleDB: agent_transactions hypertable.
--
-- Phase 2 / Day 15. The 100-feature extractor reads 30-day transaction
-- windows per agent, per epoch, across every tracked agent. A plain
-- PostgreSQL table cannot serve that scan pattern at scale. This migration
-- moves the TIME-SERIES — agent_transactions — onto a TimescaleDB
-- hypertable: time-partitioned, compressed, with continuous aggregates
-- pre-rolling the windows the feature extractor and baseline engine need.
--
-- RELATIONAL STATE STAYS PUT. Registrations, scores, operators, and
-- monitoring tables remain plain PostgreSQL — they are keyed lookups and
-- joins, not time-range scans, and gain nothing from a hypertable. Only
-- the time-series moves.
--
-- NOTE ON NUMBERING: the Doc-2 brief labels this migration "0008", but
-- 0008 was already taken by the Day-13 scores-v2 migration. This file is
-- 0009 — the next free ordinal — and is otherwise exactly the TimescaleDB
-- migration the brief describes.
--
-- IDEMPOTENT + SAFE: every statement is guarded (IF NOT EXISTS / ON
-- CONFLICT). The backfill (0009_backfill_transactions.py) runs separately
-- so this DDL migration stays fast and transactional.
-- =============================================================================

INSERT INTO schema_version (version, description) VALUES
    (9, 'TimescaleDB: agent_transactions hypertable + continuous aggregates')
ON CONFLICT (version) DO NOTHING;


-- ── 0. The TimescaleDB extension ─────────────────────────────────────────────
-- Production runs on a TimescaleDB image, where the extension is available.
-- The unit/integration test harness still uses plain postgres:16-alpine; this
-- migration must remain runnable there so non-timeseries tests do not fail
-- before they start. When TimescaleDB is absent we create the same relational
-- table + materialized-view shape, and skip hypertable/compression policies.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb'
    ) THEN
        CREATE EXTENSION IF NOT EXISTS timescaledb;
    END IF;
END $$;


-- ── 1. agent_transactions — the base table ───────────────────────────────────
--
-- Columns mirror the Python `Transaction` dataclass exactly (features/types.py).
-- `program_ids` is a TEXT[] — the ordered list of invoked programs.
--
-- PRIMARY KEY: a hypertable's unique constraints MUST include the
-- partitioning column (block_time). (signature, block_time) is unique —
-- a Solana signature is globally unique, block_time is carried for the
-- partition key.

CREATE TABLE IF NOT EXISTS agent_transactions (
    id               BIGSERIAL,
    agent_wallet     TEXT         NOT NULL,
    tx_signature     TEXT,
    signature        TEXT         NOT NULL,
    slot             BIGINT       NOT NULL,
    block_time       TIMESTAMPTZ  NOT NULL,
    success          BOOLEAN      NOT NULL,
    program_ids      TEXT[]       NOT NULL DEFAULT '{}',
    sol_change       BIGINT       NOT NULL DEFAULT 0,
    fee              BIGINT       NOT NULL DEFAULT 0,
    priority_fee     BIGINT       NOT NULL DEFAULT 0,
    compute_units    BIGINT       NOT NULL DEFAULT 0,
    counterparty     TEXT,
    raw_meta         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    received_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    source           TEXT         NOT NULL DEFAULT 'webhook'
        CHECK (source IN ('webhook','backfill','replay','e2e_seed')),
    ingested_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),

    PRIMARY KEY (signature, block_time)
);

-- Day 15 upgrades the legacy MVP table shape in-place. The MVP ingestion
-- path used `tx_signature`; the new repository uses `signature`. Keep both
-- columns for compatibility and make them aliases at write time.
ALTER TABLE agent_transactions
    ADD COLUMN IF NOT EXISTS signature TEXT,
    ADD COLUMN IF NOT EXISTS tx_signature TEXT,
    ADD COLUMN IF NOT EXISTS priority_fee BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS compute_units BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS counterparty TEXT,
    ADD COLUMN IF NOT EXISTS raw_meta JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'webhook',
    ADD COLUMN IF NOT EXISTS ingested_at TIMESTAMPTZ NOT NULL DEFAULT now();

UPDATE agent_transactions
   SET signature = tx_signature
 WHERE signature IS NULL
   AND tx_signature IS NOT NULL;

UPDATE agent_transactions
   SET tx_signature = signature
 WHERE tx_signature IS NULL
   AND signature IS NOT NULL;

CREATE OR REPLACE FUNCTION sync_agent_transaction_signature()
RETURNS trigger AS $$
BEGIN
    IF NEW.signature IS NULL AND NEW.tx_signature IS NOT NULL THEN
        NEW.signature := NEW.tx_signature;
    END IF;
    IF NEW.tx_signature IS NULL AND NEW.signature IS NOT NULL THEN
        NEW.tx_signature := NEW.signature;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sync_agent_transaction_signature
    ON agent_transactions;
CREATE TRIGGER trg_sync_agent_transaction_signature
BEFORE INSERT OR UPDATE ON agent_transactions
FOR EACH ROW
EXECUTE FUNCTION sync_agent_transaction_signature();

-- The old schema had a unique tx_signature index/constraint. A TimescaleDB
-- hypertable cannot keep unique constraints that omit the partitioning
-- column, so Day 15 moves idempotency to (signature, block_time).
DROP INDEX IF EXISTS idx_tx_sig;
ALTER TABLE agent_transactions
    DROP CONSTRAINT IF EXISTS agent_transactions_tx_signature_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_tx_signature_time
    ON agent_transactions (signature, block_time);


-- ── 2. Promote to a hypertable ───────────────────────────────────────────────
--
-- chunk_time_interval = 1 day. The feature extractor's primary window is
-- 30 days; daily chunks mean a 30-day scan touches ~30 chunks and the
-- planner prunes everything outside the range. Smaller chunks would
-- multiply planning overhead; larger chunks would scan slack data.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable(
            'agent_transactions',
            'block_time',
            chunk_time_interval => INTERVAL '1 day',
            if_not_exists       => TRUE,
            migrate_data        => TRUE        -- absorb any pre-existing rows
        );
    END IF;
END $$;


-- ── 3. Indexes ───────────────────────────────────────────────────────────────
--
-- The dominant query is "all of agent X's transactions in [t0, t1]".
-- A composite (agent_wallet, block_time DESC) index on top of the
-- partition pruning makes that an index range scan within each chunk.

CREATE INDEX IF NOT EXISTS idx_agent_tx_wallet_time
    ON agent_transactions (agent_wallet, block_time DESC);

-- Signature lookups (dedup on ingest, point lookups).
CREATE INDEX IF NOT EXISTS idx_agent_tx_signature
    ON agent_transactions (signature);


-- ── 4. Compression ───────────────────────────────────────────────────────────
--
-- Transactions are immutable once ingested. Chunks older than 7 days are
-- compressed: TimescaleDB's columnar compression on this shape typically
-- reaches ~10-20x. `segmentby = agent_wallet` keeps each agent's rows
-- contiguous within a compressed chunk, so a per-agent window scan over
-- compressed data stays a localised read.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        ALTER TABLE agent_transactions SET (
            timescaledb.compress,
            timescaledb.compress_segmentby = 'agent_wallet',
            timescaledb.compress_orderby   = 'block_time DESC'
        );
    END IF;
END $$;

-- Auto-compress chunks once they age past the 7-day active window.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM add_compression_policy(
            'agent_transactions',
            INTERVAL '7 days',
            if_not_exists => TRUE
        );
    END IF;
END $$;


-- ── 5. Continuous aggregate — daily per-agent rollup ─────────────────────────
--
-- The feature extractor and baseline engine repeatedly need per-active-day
-- rollups: transaction count, success rate, fee totals, distinct
-- counterparties. The `daily_success_rate_series` (baseline v3, migration
-- 0007) is exactly this. A continuous aggregate MATERIALISES the rollup
-- and refreshes incrementally — a 30-day series becomes a 30-row read of a
-- pre-computed view instead of an aggregate over ~thousands of raw rows.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        EXECUTE $view$
            CREATE MATERIALIZED VIEW IF NOT EXISTS agent_tx_daily
            WITH (timescaledb.continuous) AS
            SELECT
                agent_wallet,
                time_bucket(INTERVAL '1 day', block_time)        AS day,
                count(*)                                          AS tx_count,
                count(*) FILTER (WHERE success)                   AS success_count,
                avg(CASE WHEN success THEN 1.0 ELSE 0.0 END)      AS success_rate,
                sum(sol_change)                                   AS net_sol_change,
                sum(fee + priority_fee)                           AS total_fees,
                count(DISTINCT counterparty)                      AS distinct_counterparties
            FROM agent_transactions
            GROUP BY agent_wallet, day
            WITH NO DATA
        $view$;
    ELSE
        EXECUTE $view$
            CREATE MATERIALIZED VIEW IF NOT EXISTS agent_tx_daily AS
            SELECT
                agent_wallet,
                date_trunc('day', block_time)                     AS day,
                count(*)                                          AS tx_count,
                count(*) FILTER (WHERE success)                   AS success_count,
                avg(CASE WHEN success THEN 1.0 ELSE 0.0 END)      AS success_rate,
                sum(sol_change)                                   AS net_sol_change,
                sum(fee + priority_fee)                           AS total_fees,
                count(DISTINCT counterparty)                      AS distinct_counterparties
            FROM agent_transactions
            GROUP BY agent_wallet, day
            WITH NO DATA
        $view$;
    END IF;
END $$;

-- Refresh policy: keep the materialised rollup current. The most recent
-- day is left to the real-time aggregation layer (start_offset bounds the
-- materialised range; rows newer than end_offset are computed on read).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM add_continuous_aggregate_policy(
            'agent_tx_daily',
            start_offset      => INTERVAL '90 days',
            end_offset        => INTERVAL '1 hour',
            schedule_interval => INTERVAL '1 hour',
            if_not_exists     => TRUE
        );
    END IF;
END $$;


-- ── 6. Retention ─────────────────────────────────────────────────────────────
--
-- Raw transactions older than 180 days are dropped — well beyond the
-- 30-day feature window and the baseline horizon. The daily continuous
-- aggregate (which the longer-horizon analytics use) is retained longer
-- by virtue of being a separate, far smaller hypertable.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM add_retention_policy(
            'agent_transactions',
            INTERVAL '180 days',
            if_not_exists => TRUE
        );
    END IF;
END $$;


COMMENT ON TABLE agent_transactions IS
    'Time-series of agent Solana transactions. TimescaleDB hypertable, '
    '1-day chunks, compressed past 7 days, 180-day retention (Day 15).';
COMMENT ON MATERIALIZED VIEW agent_tx_daily IS
    'Continuous aggregate: per-agent per-day transaction rollup. Serves the '
    'feature extractor''s daily-window queries and the baseline daily series.';
