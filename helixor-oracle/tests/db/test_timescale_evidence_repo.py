"""
tests/db/test_timescale_evidence_repo.py — the Day-39 DA repo.

`TimescaleEvidencePayloadRepo` is exercised against a FAKE `DBConnection`
that records every (sql, params) pair and returns canned rows. The DDL
that the SQL targets is validated separately by migration 0010 running
against a live TimescaleDB in deployment; here we pin the query
construction + the row -> EvidencePayloadRecord mapping.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest

from api.evidence_repo import EvidencePayloadRecord
from db.timescale_evidence_repo import (
    EvidenceConflictError,
    TimescaleEvidencePayloadRepo,
)


# =============================================================================
# Helpers
# =============================================================================

WALLET_A = "A1" * 22
REF_TS = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def _canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _make_record(
    *, wallet=WALLET_A, epoch=29, on_chain_hash=None,
) -> EvidencePayloadRecord:
    payload_bytes = _canonical({
        "taxonomy_version": "1", "kernel_manifest": "a" * 64,
        "dimensions": [], "findings": [],
    })
    return EvidencePayloadRecord(
        agent_wallet=wallet,
        epoch=epoch,
        payload_bytes=payload_bytes,
        payload_hash=hashlib.sha256(payload_bytes).digest(),
        taxonomy_version=1,
        signer_count=5,
        computed_at=REF_TS,
        on_chain_hash=on_chain_hash,
    )


# =============================================================================
# A fake DBConnection — records (sql, params); returns canned rows
# =============================================================================

class FakeConnection:

    def __init__(self) -> None:
        self.calls: list[tuple[str, list]] = []
        self._responses: dict[str, list[tuple]] = {}
        self._next_raise: Exception | None = None

    def set_response(self, sql_fragment: str, rows: list[tuple]) -> None:
        self._responses[sql_fragment] = rows

    def raise_on_next(self, exc: Exception) -> None:
        self._next_raise = exc

    def execute(self, sql: str, params) -> list[tuple]:
        self.calls.append((sql, list(params)))
        if self._next_raise is not None:
            exc = self._next_raise
            self._next_raise = None
            raise exc
        for fragment, rows in self._responses.items():
            if fragment in sql:
                return rows
        return []


# =============================================================================
# A — add() path
# =============================================================================

class TestAdd:

    def test_insert_binds_every_column(self):
        conn = FakeConnection()
        repo = TimescaleEvidencePayloadRepo(conn)
        rec = _make_record()
        repo.add(rec)
        assert len(conn.calls) == 1
        sql, params = conn.calls[0]
        assert "INSERT INTO diagnosis_payloads" in sql
        assert "ON CONFLICT (payload_hash) DO NOTHING" in sql
        assert params == [
            rec.payload_hash, rec.agent_wallet, rec.epoch,
            rec.payload_bytes, rec.taxonomy_version, rec.signer_count,
            rec.on_chain_hash, rec.computed_at,
        ]

    def test_re_insert_same_hash_is_idempotent(self):
        """The ON CONFLICT (payload_hash) clause makes the duplicate-
        hash INSERT a no-op at the driver level. The repo issues the
        INSERT both times — the database absorbs the conflict."""
        conn = FakeConnection()
        repo = TimescaleEvidencePayloadRepo(conn)
        rec = _make_record()
        repo.add(rec)
        repo.add(rec)
        assert len(conn.calls) == 2

    def test_divergent_agent_epoch_raises_conflict(self):
        conn = FakeConnection()
        repo = TimescaleEvidencePayloadRepo(conn)
        conn.raise_on_next(
            RuntimeError("duplicate key value violates unique constraint "
                         "uq_diagnosis_payloads_agent_epoch"),
        )
        with pytest.raises(EvidenceConflictError, match="conflicting"):
            repo.add(_make_record())

    def test_non_constraint_error_propagates(self):
        conn = FakeConnection()
        repo = TimescaleEvidencePayloadRepo(conn)
        conn.raise_on_next(RuntimeError("connection reset"))
        with pytest.raises(RuntimeError, match="connection reset"):
            repo.add(_make_record())


# =============================================================================
# B — read paths
# =============================================================================

class TestRead:

    def test_evidence_at_epoch_returns_none_when_no_row(self):
        conn = FakeConnection()
        repo = TimescaleEvidencePayloadRepo(conn)
        assert repo.evidence_at_epoch(WALLET_A, 29) is None
        assert len(conn.calls) == 1
        assert "WHERE agent_wallet = %s" in conn.calls[0][0]

    def test_evidence_at_epoch_decodes_row(self):
        rec = _make_record()
        conn = FakeConnection()
        conn.set_response("WHERE agent_wallet = %s", [
            (rec.payload_hash, rec.agent_wallet, rec.epoch,
             rec.payload_bytes, rec.taxonomy_version, rec.signer_count,
             rec.on_chain_hash, rec.computed_at),
        ])
        repo = TimescaleEvidencePayloadRepo(conn)
        out = repo.evidence_at_epoch(WALLET_A, 29)
        assert out is not None
        assert out.payload_hash == rec.payload_hash
        assert out.payload_bytes == rec.payload_bytes
        assert out.signer_count == 5

    def test_by_hash_decodes_row(self):
        rec = _make_record(on_chain_hash=b"\xab" * 32)
        conn = FakeConnection()
        conn.set_response("WHERE payload_hash = %s", [
            (rec.payload_hash, rec.agent_wallet, rec.epoch,
             rec.payload_bytes, rec.taxonomy_version, rec.signer_count,
             rec.on_chain_hash, rec.computed_at),
        ])
        repo = TimescaleEvidencePayloadRepo(conn)
        out = repo.by_hash(rec.payload_hash)
        assert out is not None
        assert out.on_chain_hash == b"\xab" * 32

    def test_by_hash_wrong_length_rejected(self):
        conn = FakeConnection()
        repo = TimescaleEvidencePayloadRepo(conn)
        with pytest.raises(ValueError, match="32 bytes"):
            repo.by_hash(b"\xab" * 16)


# =============================================================================
# C — record_on_chain_hash
# =============================================================================

class TestRecordOnChainHash:

    def test_update_binds_hash_wallet_epoch(self):
        conn = FakeConnection()
        repo = TimescaleEvidencePayloadRepo(conn)
        repo.record_on_chain_hash(WALLET_A, 29, b"\xcd" * 32)
        assert len(conn.calls) == 1
        sql, params = conn.calls[0]
        assert "UPDATE diagnosis_payloads" in sql
        assert "SET on_chain_hash" in sql
        assert params == [b"\xcd" * 32, WALLET_A, 29]

    def test_wrong_length_rejected(self):
        conn = FakeConnection()
        repo = TimescaleEvidencePayloadRepo(conn)
        with pytest.raises(ValueError, match="32 bytes"):
            repo.record_on_chain_hash(WALLET_A, 29, b"\xcd" * 16)
