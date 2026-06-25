"""
tests/oracle/test_dp1_data_subject_request.py — DSAR substrate pins.

The DSAR module is the runtime path GDPR Art. 15 / Art. 17, DPDP
s.11 / s.12, and CCPA §1798.110 / §1798.105 are satisfied through.
These tests pin:

  - wallet validation rejects non-base58 input (VULN-20 carryover)
  - query enumerates EVERY policy slice (erasable + carved out)
  - query SQL is the audit-pinned `agent_transactions` /
    `agent_scores` parameterised template (no f-string splicing)
  - erase requires a non-empty justification
  - erase only deletes from slices wired into `_SQL_TEMPLATES`
  - erase explicitly carves out on-chain + REFUSAL_LOG + Kafka +
    Prometheus, with the documented reason strings
  - the audit event is canonical JSON (sorted keys, byte-identical
    round-trip)
  - a query's audit event vs an erase's audit event differ only
    in the documented fields
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from oracle.data_protection_policy import (
    DataCategory,
    RETENTION_POLICIES,
    StorageLocation,
)
from oracle.data_subject_request import (
    CARVE_OUT_KAFKA_RETENTION,
    CARVE_OUT_ON_CHAIN,
    CARVE_OUT_PROMETHEUS_RETENTION,
    CARVE_OUT_REFUSAL_LOG,
    DSAROperation,
    DSAR_AUDIT_WIRE_VERSION,
    DataSubjectErasureReport,
    DataSubjectQueryReport,
    SliceOutcome,
    WalletValidationError,
    erase_data_subject,
    query_data_subject,
    serialize_dsar_audit_event,
)


# ----------------------------------------------------------------------------
# A fake DBConnection capturing every (sql, params) call. Returns
# scripted row sets keyed by query.
# ----------------------------------------------------------------------------

class _FakeDB:
    def __init__(self, count_rows: dict[str, int] | None = None):
        self.calls: list[tuple[str, tuple]] = []
        # Map SQL prefix → count to return on COUNT(*) queries.
        self._counts = count_rows or {}

    def execute(self, sql: str, params):
        self.calls.append((sql, tuple(params)))
        if sql.startswith("SELECT COUNT(*) FROM agent_transactions"):
            return [(self._counts.get("transactions", 0),)]
        if sql.startswith("SELECT COUNT(*) FROM agent_scores"):
            return [(self._counts.get("scores", 0),)]
        return []


# Valid base58 wallet (44 chars, base58 alphabet)
_VALID_WALLET = "4r19C7rk6E1RbQTfniqWh2xVynQqmw9P2Z2a3K4LPREf"
_NOW = datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc)


# ----------------------------------------------------------------------------
# Wallet validation
# ----------------------------------------------------------------------------

def test_query_rejects_non_base58_wallet():
    db = _FakeDB()
    with pytest.raises(WalletValidationError):
        query_data_subject("not-base58!", db=db, detected_at=_NOW)


def test_query_rejects_short_wallet():
    db = _FakeDB()
    with pytest.raises(WalletValidationError):
        query_data_subject("aaaa", db=db, detected_at=_NOW)


def test_erase_rejects_non_base58_wallet():
    db = _FakeDB()
    with pytest.raises(WalletValidationError):
        erase_data_subject(
            "not-base58!", "ticket #DSAR-1", db=db, detected_at=_NOW,
        )


# ----------------------------------------------------------------------------
# Query — enumerates every policy slice
# ----------------------------------------------------------------------------

def test_query_enumerates_every_policy_slice():
    db = _FakeDB(count_rows={"transactions": 42, "scores": 7})
    report = query_data_subject(
        _VALID_WALLET, db=db, detected_at=_NOW,
    )
    assert isinstance(report, DataSubjectQueryReport)
    assert len(report.slices) == len(RETENTION_POLICIES)


def test_query_returns_actual_row_counts_for_erasable_slices():
    db = _FakeDB(count_rows={"transactions": 42, "scores": 7})
    report = query_data_subject(
        _VALID_WALLET, db=db, detected_at=_NOW,
    )
    by_key = {(s.category, s.storage_location): s for s in report.slices}
    tx_slice = by_key[
        (DataCategory.TRANSACTION_HISTORY,
         StorageLocation.OFF_CHAIN_TIMESCALE)
    ]
    score_slice = by_key[
        (DataCategory.SCORE_HISTORY,
         StorageLocation.OFF_CHAIN_TIMESCALE)
    ]
    assert tx_slice.record_count == 42
    assert score_slice.record_count == 7
    assert tx_slice.erasure_applied is False  # QUERY never deletes
    assert score_slice.erasure_applied is False


def test_query_does_not_delete():
    db = _FakeDB()
    query_data_subject(_VALID_WALLET, db=db, detected_at=_NOW)
    for sql, _ in db.calls:
        assert not sql.startswith("DELETE"), (
            f"query op issued a DELETE: {sql!r}"
        )


def test_query_uses_parameterised_sql():
    db = _FakeDB()
    query_data_subject(_VALID_WALLET, db=db, detected_at=_NOW)
    for sql, params in db.calls:
        assert "%s" in sql
        assert _VALID_WALLET in params  # wallet went via params, not splice


# ----------------------------------------------------------------------------
# Query — carve-outs surfaced
# ----------------------------------------------------------------------------

def test_query_surfaces_on_chain_carve_out():
    db = _FakeDB()
    report = query_data_subject(_VALID_WALLET, db=db, detected_at=_NOW)
    on_chain_slices = [
        s for s in report.slices
        if s.storage_location is StorageLocation.ON_CHAIN_SOLANA
    ]
    assert on_chain_slices, "no on-chain slices surfaced"
    for s in on_chain_slices:
        assert s.carve_out_reason == CARVE_OUT_ON_CHAIN
        assert s.erasure_applied is False


def test_query_surfaces_refusal_log_carve_out():
    db = _FakeDB()
    report = query_data_subject(_VALID_WALLET, db=db, detected_at=_NOW)
    refusal = next(
        s for s in report.slices
        if s.category is DataCategory.REFUSAL_LOG
    )
    assert refusal.carve_out_reason == CARVE_OUT_REFUSAL_LOG


def test_query_surfaces_kafka_retention_carve_out():
    db = _FakeDB()
    report = query_data_subject(_VALID_WALLET, db=db, detected_at=_NOW)
    kafka_tx = next(
        s for s in report.slices
        if s.category is DataCategory.TRANSACTION_HISTORY
        and s.storage_location is StorageLocation.OFF_CHAIN_KAFKA
    )
    assert kafka_tx.carve_out_reason == CARVE_OUT_KAFKA_RETENTION


def test_query_surfaces_prometheus_retention_carve_out():
    db = _FakeDB()
    report = query_data_subject(_VALID_WALLET, db=db, detected_at=_NOW)
    prom = next(
        s for s in report.slices
        if s.storage_location is StorageLocation.OFF_CHAIN_PROMETHEUS
    )
    assert prom.carve_out_reason == CARVE_OUT_PROMETHEUS_RETENTION


# ----------------------------------------------------------------------------
# Erase — justification + delete behavior
# ----------------------------------------------------------------------------

def test_erase_requires_non_empty_justification():
    db = _FakeDB()
    with pytest.raises(ValueError, match="justification must be non-empty"):
        erase_data_subject(
            _VALID_WALLET, "", db=db, detected_at=_NOW,
        )
    with pytest.raises(ValueError, match="justification must be non-empty"):
        erase_data_subject(
            _VALID_WALLET, "   ", db=db, detected_at=_NOW,
        )


def test_erase_issues_delete_only_for_wired_slices():
    db = _FakeDB(count_rows={"transactions": 5, "scores": 3})
    erase_data_subject(
        _VALID_WALLET, "ticket #DSAR-1",
        db=db, detected_at=_NOW,
    )
    delete_sqls = [sql for sql, _ in db.calls if sql.startswith("DELETE")]
    # Two erasable slices in DP-1 today: transactions + scores.
    assert sorted(delete_sqls) == sorted([
        "DELETE FROM agent_transactions WHERE agent_wallet = %s",
        "DELETE FROM agent_scores WHERE agent_wallet = %s",
    ])


def test_erase_records_count_before_deletion():
    """The erasure report's record_count for an erased slice is the
    pre-deletion count (i.e. how many rows we actually deleted)."""
    db = _FakeDB(count_rows={"transactions": 42, "scores": 7})
    report = erase_data_subject(
        _VALID_WALLET, "ticket #DSAR-1",
        db=db, detected_at=_NOW,
    )
    by_key = {(s.category, s.storage_location): s for s in report.slices}
    tx = by_key[
        (DataCategory.TRANSACTION_HISTORY,
         StorageLocation.OFF_CHAIN_TIMESCALE)
    ]
    assert tx.record_count == 42
    assert tx.erasure_applied is True


def test_erase_does_not_touch_on_chain_or_refusal_log():
    db = _FakeDB()
    report = erase_data_subject(
        _VALID_WALLET, "ticket #DSAR-1",
        db=db, detected_at=_NOW,
    )
    # No DELETE issued against on-chain or refusal-log targets.
    delete_targets = [
        sql.split()[2] for sql, _ in db.calls if sql.startswith("DELETE")
    ]
    assert "cert_refusals" not in str(delete_targets).lower()
    assert "HealthCertificate" not in str(delete_targets)

    # Carve-outs surfaced in report.
    for s in report.slices:
        if s.storage_location is StorageLocation.ON_CHAIN_SOLANA:
            assert s.carve_out_reason == CARVE_OUT_ON_CHAIN
            assert s.erasure_applied is False
        if s.category is DataCategory.REFUSAL_LOG:
            assert s.carve_out_reason == CARVE_OUT_REFUSAL_LOG
            assert s.erasure_applied is False


def test_erase_total_erased_matches_sum_of_erased_slices():
    db = _FakeDB(count_rows={"transactions": 42, "scores": 7})
    report = erase_data_subject(
        _VALID_WALLET, "ticket #DSAR-1",
        db=db, detected_at=_NOW,
    )
    assert report.total_erased == 42 + 7


# ----------------------------------------------------------------------------
# SliceOutcome invariants
# ----------------------------------------------------------------------------

def test_slice_outcome_rejects_negative_count():
    with pytest.raises(ValueError, match=">= 0"):
        SliceOutcome(
            category=DataCategory.TRANSACTION_HISTORY,
            storage_location=StorageLocation.OFF_CHAIN_TIMESCALE,
            record_count=-1,
            erasure_applied=False,
            carve_out_reason=None,
        )


def test_slice_outcome_rejects_applied_plus_carve_out():
    with pytest.raises(ValueError, match="mutually exclusive"):
        SliceOutcome(
            category=DataCategory.TRANSACTION_HISTORY,
            storage_location=StorageLocation.OFF_CHAIN_TIMESCALE,
            record_count=1,
            erasure_applied=True,
            carve_out_reason="oops",
        )


# ----------------------------------------------------------------------------
# Audit event canonicalisation
# ----------------------------------------------------------------------------

def test_audit_event_is_canonical_json():
    """Two operators producing the same audit event get byte-identical
    output (sorted keys, fixed key order)."""
    db = _FakeDB(count_rows={"transactions": 42, "scores": 7})
    report = erase_data_subject(
        _VALID_WALLET, "ticket #DSAR-1",
        db=db, detected_at=_NOW,
    )
    a = serialize_dsar_audit_event(
        operation=DSAROperation.ERASE,
        wallet=_VALID_WALLET,
        justification="ticket #DSAR-1",
        slices=report.slices,
        detected_at=_NOW,
    )
    b = serialize_dsar_audit_event(
        operation=DSAROperation.ERASE,
        wallet=_VALID_WALLET,
        justification="ticket #DSAR-1",
        slices=report.slices,
        detected_at=_NOW,
    )
    assert a == b
    # Round-trip into JSON to confirm.
    decoded = json.loads(a)
    assert decoded["wire_version"] == DSAR_AUDIT_WIRE_VERSION
    assert decoded["operation"] == "erase"
    assert decoded["wallet"] == _VALID_WALLET
    assert decoded["justification"] == "ticket #DSAR-1"
    assert decoded["detected_at"].endswith("Z")


def test_audit_event_query_vs_erase_differ_in_op_and_justification():
    db = _FakeDB(count_rows={"transactions": 1, "scores": 1})
    q_report = query_data_subject(
        _VALID_WALLET, db=db, detected_at=_NOW,
    )
    e_report = erase_data_subject(
        _VALID_WALLET, "ticket #DSAR-1",
        db=_FakeDB(count_rows={"transactions": 1, "scores": 1}),
        detected_at=_NOW,
    )
    q_event = json.loads(serialize_dsar_audit_event(
        operation=DSAROperation.QUERY,
        wallet=_VALID_WALLET,
        justification=None,
        slices=q_report.slices,
        detected_at=_NOW,
    ))
    e_event = json.loads(serialize_dsar_audit_event(
        operation=DSAROperation.ERASE,
        wallet=_VALID_WALLET,
        justification="ticket #DSAR-1",
        slices=e_report.slices,
        detected_at=_NOW,
    ))
    assert q_event["operation"] == "query"
    assert e_event["operation"] == "erase"
    assert q_event["justification"] == ""
    assert e_event["justification"] == "ticket #DSAR-1"


def test_audit_event_naive_datetime_rejected():
    with pytest.raises(ValueError, match="tz-aware UTC"):
        serialize_dsar_audit_event(
            operation=DSAROperation.QUERY,
            wallet=_VALID_WALLET,
            justification=None,
            slices=(),
            detected_at=datetime(2026, 5, 27, 12, 0, 0),  # naive
        )
