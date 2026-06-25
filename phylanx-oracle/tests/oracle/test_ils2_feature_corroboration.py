"""
tests/oracle/test_ils2_feature_corroboration.py — ILS-2 producer-
corroboration + record-freshness floor.

Pins:
  - Constants (MIN_DISTINCT_PRODUCERS_PER_AGGREGATION=2,
    MAX_PRODUCER_DOMINANCE_RATIO=0.7, MAX_RECORD_AGE_SECONDS=24h,
    RECORD_FUTURE_TOLERANCE_SECONDS=60).
  - Healthy aggregation with 3 distinct producers and balanced load
    is OK.
  - Empty aggregation refused with NO_RECORDS.
  - Single-producer aggregation refused with TOO_FEW_PRODUCERS.
  - Exactly 2 distinct producers (the floor) is OK.
  - Inclusive boundary: ratio exactly 0.7 is OK; 0.71 refused.
  - Stale records (> 24h) refused with RECORDS_TOO_STALE.
  - Future-dated records refused with RECORD_TIMESTAMP_IN_FUTURE.
  - Small clock skew (< 60s) tolerated.
  - Multiple violations reported together.
  - Enforcement raises FeatureCorroborationError on refusal.
  - Audit-scenario: attacker with one compromised producer key
    stamps 100% of records — REFUSED with TOO_FEW_PRODUCERS +
    PRODUCER_OVER_DOMINANCE.
  - Audit-scenario: attacker backfills records claiming to be 30h
    old — REFUSED at the freshness floor.
"""

from __future__ import annotations

import pytest

from oracle.feature_corroboration import (
    CORROBORATION_OK,
    CORROBORATION_REFUSED,
    FeatureAggregation,
    FeatureCorroborationError,
    FeatureRecord,
    MAX_PRODUCER_DOMINANCE_RATIO,
    MAX_RECORD_AGE_SECONDS,
    MIN_DISTINCT_PRODUCERS_PER_AGGREGATION,
    REASON_NO_RECORDS,
    REASON_PRODUCER_OVER_DOMINANCE,
    REASON_RECORDS_TOO_STALE,
    REASON_RECORD_TIMESTAMP_IN_FUTURE,
    REASON_TOO_FEW_PRODUCERS,
    RECORD_FUTURE_TOLERANCE_SECONDS,
    enforce_feature_corroboration,
    verify_feature_corroboration,
)


NOW = 1_700_000_000
AGENT = "agent-wallet"


def _rec(producer: str, age_seconds: int = 0) -> FeatureRecord:
    return FeatureRecord(
        producer_pubkey=producer,
        produced_unix=NOW - age_seconds,
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert MIN_DISTINCT_PRODUCERS_PER_AGGREGATION == 2
    assert MAX_PRODUCER_DOMINANCE_RATIO == 0.7
    assert MAX_RECORD_AGE_SECONDS == 24 * 3600
    assert RECORD_FUTURE_TOLERANCE_SECONDS == 60


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_healthy_three_producer_aggregation_is_ok():
    agg = FeatureAggregation(
        agent_wallet=AGENT,
        records=tuple(_rec("p1") for _ in range(4))
              + tuple(_rec("p2") for _ in range(3))
              + tuple(_rec("p3") for _ in range(3)),
    )
    report = verify_feature_corroboration(agg, current_unix=NOW)
    assert report.is_allowed
    assert report.status == CORROBORATION_OK
    assert report.producer_count == 3
    assert report.dominance_ratio == 0.4


def test_exactly_two_producers_is_ok():
    # Floor is 2 — exactly 2 distinct producers must be accepted.
    agg = FeatureAggregation(
        agent_wallet=AGENT,
        records=(_rec("p1"), _rec("p1"), _rec("p2"), _rec("p2")),
    )
    report = verify_feature_corroboration(agg, current_unix=NOW)
    assert report.is_allowed
    assert report.producer_count == 2


# ---------------------------------------------------------------------------
# Producer-count floor
# ---------------------------------------------------------------------------

def test_empty_aggregation_refused():
    agg = FeatureAggregation(agent_wallet=AGENT, records=())
    report = verify_feature_corroboration(agg, current_unix=NOW)
    assert not report.is_allowed
    assert REASON_NO_RECORDS in report.reasons


def test_single_producer_refused():
    agg = FeatureAggregation(
        agent_wallet=AGENT,
        records=tuple(_rec("p1") for _ in range(10)),
    )
    report = verify_feature_corroboration(agg, current_unix=NOW)
    assert not report.is_allowed
    assert REASON_TOO_FEW_PRODUCERS in report.reasons
    assert REASON_PRODUCER_OVER_DOMINANCE in report.reasons


# ---------------------------------------------------------------------------
# Dominance cap
# ---------------------------------------------------------------------------

def test_exactly_seventy_percent_is_ok():
    # 7 / 10 = 0.7 — inclusive at the cap.
    agg = FeatureAggregation(
        agent_wallet=AGENT,
        records=tuple(_rec("p1") for _ in range(7))
              + tuple(_rec("p2") for _ in range(3)),
    )
    report = verify_feature_corroboration(agg, current_unix=NOW)
    assert report.is_allowed


def test_seventy_one_percent_refused():
    # 71 / 100 = 0.71 — past the cap.
    agg = FeatureAggregation(
        agent_wallet=AGENT,
        records=tuple(_rec("p1") for _ in range(71))
              + tuple(_rec("p2") for _ in range(29)),
    )
    report = verify_feature_corroboration(agg, current_unix=NOW)
    assert not report.is_allowed
    assert REASON_PRODUCER_OVER_DOMINANCE in report.reasons
    assert report.dominant_producer == "p1"


# ---------------------------------------------------------------------------
# Freshness floor
# ---------------------------------------------------------------------------

def test_stale_records_refused():
    # Record 30h old (past 24h floor).
    agg = FeatureAggregation(
        agent_wallet=AGENT,
        records=(
            _rec("p1", age_seconds=30 * 3600),
            _rec("p2", age_seconds=1 * 3600),
        ),
    )
    report = verify_feature_corroboration(agg, current_unix=NOW)
    assert not report.is_allowed
    assert REASON_RECORDS_TOO_STALE in report.reasons
    assert report.stale_record_count == 1


def test_record_exactly_at_floor_is_ok():
    # Exactly 24h old — INCLUSIVE at the floor (current - produced
    # == MAX_RECORD_AGE_SECONDS is OK; > is REFUSED).
    agg = FeatureAggregation(
        agent_wallet=AGENT,
        records=(
            _rec("p1", age_seconds=MAX_RECORD_AGE_SECONDS),
            _rec("p2", age_seconds=1 * 3600),
        ),
    )
    report = verify_feature_corroboration(agg, current_unix=NOW)
    assert report.is_allowed
    assert report.stale_record_count == 0


# ---------------------------------------------------------------------------
# Time-travel defence
# ---------------------------------------------------------------------------

def test_future_dated_record_refused():
    # Record 10 minutes in the future.
    agg = FeatureAggregation(
        agent_wallet=AGENT,
        records=(
            FeatureRecord(producer_pubkey="p1", produced_unix=NOW + 600),
            _rec("p2"),
        ),
    )
    report = verify_feature_corroboration(agg, current_unix=NOW)
    assert not report.is_allowed
    assert REASON_RECORD_TIMESTAMP_IN_FUTURE in report.reasons
    assert report.future_record_count == 1


def test_small_clock_skew_tolerated():
    # 30s in the future — within tolerance.
    agg = FeatureAggregation(
        agent_wallet=AGENT,
        records=(
            FeatureRecord(producer_pubkey="p1", produced_unix=NOW + 30),
            _rec("p2"),
        ),
    )
    report = verify_feature_corroboration(agg, current_unix=NOW)
    assert report.is_allowed


# ---------------------------------------------------------------------------
# Compound violations
# ---------------------------------------------------------------------------

def test_multiple_violations_reported_together():
    # One producer dominates AND records are stale.
    agg = FeatureAggregation(
        agent_wallet=AGENT,
        records=tuple(
            _rec("p1", age_seconds=30 * 3600) for _ in range(8)
        ) + (_rec("p2"), _rec("p3")),
    )
    report = verify_feature_corroboration(agg, current_unix=NOW)
    assert not report.is_allowed
    assert REASON_PRODUCER_OVER_DOMINANCE in report.reasons
    assert REASON_RECORDS_TOO_STALE in report.reasons


# ---------------------------------------------------------------------------
# Enforcement wrapper
# ---------------------------------------------------------------------------

def test_enforce_returns_report_on_clean_aggregation():
    agg = FeatureAggregation(
        agent_wallet=AGENT,
        records=(_rec("p1"), _rec("p2"), _rec("p3")),
    )
    report = enforce_feature_corroboration(agg, current_unix=NOW)
    assert report.is_allowed


def test_enforce_raises_on_single_producer():
    with pytest.raises(FeatureCorroborationError) as excinfo:
        enforce_feature_corroboration(
            FeatureAggregation(
                agent_wallet=AGENT,
                records=tuple(_rec("p1") for _ in range(10)),
            ),
            current_unix=NOW,
        )
    assert "ILS-2" in str(excinfo.value)
    assert excinfo.value.report.status == CORROBORATION_REFUSED


# ---------------------------------------------------------------------------
# Audit scenarios — the exact attacks the gate exists for
# ---------------------------------------------------------------------------

def test_audit_scenario_single_compromised_producer_solo_poisoning():
    # Path 2 sub-leaf 2b: attacker exfiltrates ONE trusted producer
    # key and stamps 1000 synthetic-success records for the target
    # agent. Consumer-side VULN-07 signature check passes (the key
    # IS trusted); ILS-2 refuses because every record is from one
    # producer.
    agg = FeatureAggregation(
        agent_wallet=AGENT,
        records=tuple(_rec("compromised") for _ in range(1000)),
    )
    with pytest.raises(FeatureCorroborationError) as excinfo:
        enforce_feature_corroboration(agg, current_unix=NOW)
    report = excinfo.value.report
    assert REASON_TOO_FEW_PRODUCERS in report.reasons
    assert REASON_PRODUCER_OVER_DOMINANCE in report.reasons


def test_audit_scenario_backfill_with_stale_timestamps_refused():
    # Path 2 sub-leaf 2b residual: an attacker who exfiltrated a
    # since-decommissioned trusted producer key backfills records
    # with stale `produced_unix`. The signature verifies; ILS-2
    # refuses on age.
    agg = FeatureAggregation(
        agent_wallet=AGENT,
        records=(
            _rec("legit-1", age_seconds=2 * 3600),
            _rec("backfilled", age_seconds=30 * 3600),
            _rec("backfilled", age_seconds=40 * 3600),
        ),
    )
    with pytest.raises(FeatureCorroborationError) as excinfo:
        enforce_feature_corroboration(agg, current_unix=NOW)
    assert REASON_RECORDS_TOO_STALE in excinfo.value.report.reasons
