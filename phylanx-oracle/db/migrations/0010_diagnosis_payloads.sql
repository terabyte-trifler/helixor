-- =============================================================================
-- Migration 0010 — Day-39 diagnosis_payloads DA table.
--
-- The off-chain data-availability tier for the cluster-threshold-attested
-- diagnosis evidence (Day 38 cert v2 `diagnosis_payload_hash`).
--
-- WHAT IT STORES
-- --------------
-- One row per agreed-canonical evidence payload the cluster threshold-
-- signed against. The bytes are EXACTLY what every honest node produced
-- via diagnosis/evidence_payload.py — the canonical-JSON dumper guarantees
-- byte-identical output across nodes, so an indexer that re-canonicalises
-- on read would defeat the hash contract. The payload column is the wire
-- bytes verbatim.
--
-- A consumer reads via `GET /agents/{wallet}/diagnosis/{epoch}/evidence`
-- (phylanx-api), recomputes sha256 of `payload`, and compares against the
-- on-chain cert v2 field. The API surfaces `attestation: "threshold_attested"`
-- iff `payload_hash == on-chain field` for the (agent, epoch).
--
-- STORAGE PATTERN
-- ---------------
-- Mirrors the Day-26 baseline_hash pattern:
--   * primary key = payload_hash (content-addressed dedup; re-storing the
--     same bytes is a no-op)
--   * secondary index = (agent_wallet, epoch) (the API read path)
--   * payload bytes immutable once written — divergent writes for the same
--     (agent, epoch) trigger the conflict-audit branch (see migration body)
--
-- WHY APPEND-ONLY + UNIQUE
-- ------------------------
-- A divergent (agent, epoch) write means EITHER a malicious cluster
-- emitted two payloads under the same threshold-signed hash (impossible
-- under the cluster's signing protocol) OR an indexer bug ingested a
-- conflicting record. Both deserve an alert, not a silent overwrite. The
-- UNIQUE (agent_wallet, epoch) constraint makes the second write fail
-- noisily; an audit table (out of scope here, added at conflict-time)
-- records the divergence for post-mortem.
-- =============================================================================

INSERT INTO schema_version (version, description) VALUES
    (10, 'Day-39 diagnosis_payloads: off-chain DA for cluster threshold-attested evidence')
ON CONFLICT (version) DO NOTHING;


-- ── diagnosis_payloads — the DA table ────────────────────────────────────────
--
-- payload_hash is the SHA-256 of the canonical-JSON bytes (32 bytes).
-- BYTEA so a consumer reading from the API does not pay a hex<->bytes
-- conversion round-trip; the API formats to hex at the wire seam.
--
-- payload is the canonical-JSON wire bytes the cluster signed against.
-- BYTEA (not JSONB!) — a JSONB column would re-canonicalise on read
-- and break the hash contract. The bytes are immutable.
--
-- taxonomy_version mirrors the on-chain u8 field; SMALLINT here so the
-- check constraint can range-guard it (PostgreSQL has no u8 type).
--
-- signer_count is the number of cluster signatures the cert v2 collected
-- (max 16 in Day-38 v2; SMALLINT is comfortable).

CREATE TABLE IF NOT EXISTS diagnosis_payloads (
    payload_hash         BYTEA        PRIMARY KEY,
    agent_wallet         TEXT         NOT NULL,
    epoch                BIGINT       NOT NULL,
    payload              BYTEA        NOT NULL,
    taxonomy_version     SMALLINT     NOT NULL,
    signer_count         SMALLINT     NOT NULL,
    on_chain_hash        BYTEA,                    -- NULL until cert v2 observed
    computed_at          TIMESTAMPTZ  NOT NULL,
    inserted_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT diagnosis_payloads_hash_len
        CHECK (octet_length(payload_hash) = 32),
    CONSTRAINT diagnosis_payloads_on_chain_hash_len
        CHECK (on_chain_hash IS NULL OR octet_length(on_chain_hash) = 32),
    CONSTRAINT diagnosis_payloads_payload_nonempty
        CHECK (octet_length(payload) > 0),
    CONSTRAINT diagnosis_payloads_taxonomy_u8
        CHECK (taxonomy_version >= 0 AND taxonomy_version <= 255),
    CONSTRAINT diagnosis_payloads_signers_nonneg
        CHECK (signer_count >= 0),
    CONSTRAINT diagnosis_payloads_epoch_positive
        CHECK (epoch >= 1)
);

-- The (agent, epoch) secondary index — the API's read path. UNIQUE so a
-- second, divergent payload under the same (agent, epoch) fails noisily.
-- Re-ingesting the SAME payload_hash hits the PK conflict first and the
-- writer treats it as the expected idempotent re-emit.
CREATE UNIQUE INDEX IF NOT EXISTS uq_diagnosis_payloads_agent_epoch
    ON diagnosis_payloads (agent_wallet, epoch);

-- Hex-prefix lookups (debug / audit) — fast scan by payload_hash for an
-- operator chasing a divergence report from the chain side.
CREATE INDEX IF NOT EXISTS idx_diagnosis_payloads_hash
    ON diagnosis_payloads (payload_hash);

COMMENT ON TABLE diagnosis_payloads IS
    'Day-39 off-chain DA for cluster threshold-attested diagnosis evidence. '
    'sha256(payload) == on-chain cert v2 diagnosis_payload_hash.';
COMMENT ON COLUMN diagnosis_payloads.payload IS
    'Canonical-JSON wire bytes the cluster signed against. Immutable. '
    'BYTEA (not JSONB) so re-serialisation cannot break the hash contract.';
COMMENT ON COLUMN diagnosis_payloads.on_chain_hash IS
    'Cert v2 diagnosis_payload_hash, populated when the indexer observes '
    'the cert. NULL until then; the API attestation tag flips on match.';
