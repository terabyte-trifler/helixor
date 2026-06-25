"""
tests/oracle/test_ofac1_cert_refusal_log.py — OFAC-1 silent-delist
transparency substrate.

Pins:
  - `CertRefusal` rejects empty wallet, negative epoch, empty reasons,
    naive datetime.
  - `CertRefusalLog` is append-only and `drain()` is idempotent.
  - `RefusalReason` carries every audit-pinned code.
  - `RefusalGate.OPERATOR_OVERRIDE` is present (the audit-load-bearing
    gate the OFAC-1 audit script flags hardest).
  - Factory helpers refuse to convert ALLOWED reports (a refusal log
    with non-refusal records would corrupt the auditor's signal).
  - `operator_override` requires a non-empty justification — a policy
    refusal without an auditable reason is the silent-censorship case
    OFAC-1 is designed to surface.
  - Integration with `agent_age_gate`: a refusing AgentAgeReport
    converts cleanly into a CertRefusal carrying the same reasons.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from oracle.agent_age_gate import (
    MIN_AGENT_AGE_SECONDS_FOR_GREEN,
    AgentAgeContext,
    verify_agent_age_for_tier,
)
from oracle.cert_refusal_log import (
    CertRefusal,
    CertRefusalLog,
    RefusalGate,
    RefusalReason,
    from_agent_age_report,
    from_velocity_report,
    operator_override,
)


UTC_NOW = datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc)


# ----------------------------------------------------------------------------
# CertRefusal dataclass validation
# ----------------------------------------------------------------------------

def _valid_refusal(**overrides):
    base = dict(
        agent_wallet="agent-1",
        epoch=42,
        requested_tier="GREEN",
        gate=RefusalGate.NSS_3_AGENT_AGE,
        reasons=("AGENT_SECONDS_TOO_YOUNG",),
        detected_at=UTC_NOW,
    )
    base.update(overrides)
    return CertRefusal(**base)


def test_cert_refusal_happy_path():
    r = _valid_refusal()
    assert r.agent_wallet == "agent-1"
    assert r.epoch == 42
    assert r.gate is RefusalGate.NSS_3_AGENT_AGE


def test_cert_refusal_rejects_empty_wallet():
    with pytest.raises(ValueError, match="agent_wallet must be non-empty"):
        _valid_refusal(agent_wallet="")
    with pytest.raises(ValueError, match="agent_wallet must be non-empty"):
        _valid_refusal(agent_wallet="   ")


def test_cert_refusal_rejects_negative_epoch():
    with pytest.raises(ValueError, match="epoch must be >= 0"):
        _valid_refusal(epoch=-1)


def test_cert_refusal_rejects_empty_reasons():
    # A refusal with no reason code is structurally suspect — it is
    # exactly the silent-censorship-without-justification case the
    # transparency log is designed to surface.
    with pytest.raises(ValueError, match="reasons must be non-empty"):
        _valid_refusal(reasons=())


def test_cert_refusal_rejects_naive_datetime():
    naive = datetime(2026, 5, 27, 12, 0, 0)  # no tzinfo
    with pytest.raises(ValueError, match="detected_at must be tz-aware"):
        _valid_refusal(detected_at=naive)


# ----------------------------------------------------------------------------
# CertRefusalLog behaviour
# ----------------------------------------------------------------------------

def test_cert_refusal_log_append_and_drain_preserves_order():
    log = CertRefusalLog()
    r1 = _valid_refusal(agent_wallet="agent-1", epoch=10)
    r2 = _valid_refusal(agent_wallet="agent-2", epoch=11)
    r3 = _valid_refusal(agent_wallet="agent-3", epoch=12)
    log.record(r1)
    log.record(r2)
    log.record(r3)
    assert len(log) == 3
    drained = log.drain()
    assert drained == (r1, r2, r3)


def test_cert_refusal_log_drain_clears_buffer():
    log = CertRefusalLog()
    log.record(_valid_refusal())
    assert len(log) == 1
    log.drain()
    assert len(log) == 0


def test_cert_refusal_log_double_drain_is_idempotent():
    log = CertRefusalLog()
    log.record(_valid_refusal())
    log.drain()
    # Second drain on an empty log returns ().
    assert log.drain() == ()


def test_cert_refusal_log_rejects_non_refusal_record():
    log = CertRefusalLog()
    with pytest.raises(TypeError, match="expects CertRefusal"):
        log.record("not-a-refusal")  # type: ignore[arg-type]


# ----------------------------------------------------------------------------
# Pinned reason codes — the contract the audit gate depends on
# ----------------------------------------------------------------------------

def test_reason_codes_pinned_for_audit():
    """Every audit-pinned reason code must remain in RefusalReason."""
    pinned = {
        # NSS-3
        "AGENT_SECONDS_TOO_YOUNG",
        "AGENT_EPOCHS_TOO_YOUNG",
        "AGENT_REGISTERED_IN_FUTURE",
        # FRP-3
        "CERT_REISSUE_OVERDUE",
        "CERT_REISSUE_TIMESTAMP_INVALID",
        "CERT_REISSUE_TIMESTAMP_IN_FUTURE",
        # PDS-2
        "SCORE_DELTA_EXCEEDED",
        "SCORE_VELOCITY_EXCEEDED",
        "SCORE_VELOCITY_ABSURD",
        "SCORE_TIME_TRAVEL",
        # AW-01 / AW-01-EXT
        "INPUT_COMMITMENT_MISSING",
        "INPUT_COMMITMENT_DISAGREEMENT",
        "SLOT_ANCHOR_MISSING",
        # Cluster
        "QUORUM_NOT_MET",
        "SIGNATURE_THRESHOLD_NOT_MET",
        # OFAC-1
        "OPERATOR_OVERRIDE",
    }
    actual = {m.value for m in RefusalReason}
    assert pinned <= actual, f"missing: {sorted(pinned - actual)}"


def test_operator_override_gate_pinned():
    """The audit-load-bearing OPERATOR_OVERRIDE gate must remain."""
    assert RefusalGate.OPERATOR_OVERRIDE.value == "OPERATOR-OVERRIDE"


# ----------------------------------------------------------------------------
# Factory helpers
# ----------------------------------------------------------------------------

def test_from_agent_age_report_refusal_path():
    """A refusing AgentAgeReport converts into a CertRefusal that
    preserves the agent_wallet, requested_tier, and reasons."""
    # A 1-hour-old wallet refused for GREEN.
    registered_at = int(UTC_NOW.timestamp()) - 3600
    ctx = AgentAgeContext(
        agent_wallet="agent-X",
        registered_at_unix=registered_at,
        registered_at_epoch=2,
    )
    age_report = verify_agent_age_for_tier(
        ctx,
        current_unix=int(UTC_NOW.timestamp()),
        current_epoch=3,
        tier="GREEN",
    )
    assert not age_report.is_allowed
    refusal = from_agent_age_report(age_report, epoch=3, detected_at=UTC_NOW)
    assert refusal.agent_wallet == "agent-X"
    assert refusal.epoch == 3
    assert refusal.requested_tier == "GREEN"
    assert refusal.gate is RefusalGate.NSS_3_AGENT_AGE
    assert "AGENT_SECONDS_TOO_YOUNG" in refusal.reasons


def test_from_agent_age_report_refuses_allowed_input():
    """from_agent_age_report MUST refuse to convert an allowed
    AgentAgeReport — a refusal log with non-refusal records would
    corrupt the auditor's silent-delist signal."""
    aged_unix = int(UTC_NOW.timestamp()) - MIN_AGENT_AGE_SECONDS_FOR_GREEN - 1
    ctx = AgentAgeContext(
        agent_wallet="agent-Y",
        registered_at_unix=aged_unix,
        registered_at_epoch=0,
    )
    age_report = verify_agent_age_for_tier(
        ctx,
        current_unix=int(UTC_NOW.timestamp()),
        current_epoch=200,
        tier="GREEN",
    )
    assert age_report.is_allowed
    with pytest.raises(ValueError, match="called on an allowed AgentAgeReport"):
        from_agent_age_report(age_report, epoch=200, detected_at=UTC_NOW)


def test_operator_override_requires_justification():
    """A policy refusal without justification is the silent-censorship
    case OFAC-1 is designed to surface."""
    with pytest.raises(ValueError, match="non-empty justification"):
        operator_override(
            agent_wallet="agent-1",
            epoch=42,
            requested_tier="GREEN",
            justification="",
            detected_at=UTC_NOW,
        )
    with pytest.raises(ValueError, match="non-empty justification"):
        operator_override(
            agent_wallet="agent-1",
            epoch=42,
            requested_tier="GREEN",
            justification="   ",
            detected_at=UTC_NOW,
        )


def test_operator_override_records_inline_reason():
    """The justification is folded into the reasons tuple so an
    auditor reading the topic sees the reason inline — no separate
    lookup required."""
    r = operator_override(
        agent_wallet="agent-1",
        epoch=42,
        requested_tier="GREEN",
        justification="partner revoked under AdminBadFaith, ticket INC-2026-001",
        detected_at=UTC_NOW,
    )
    assert r.gate is RefusalGate.OPERATOR_OVERRIDE
    assert len(r.reasons) == 1
    assert r.reasons[0].startswith("OPERATOR_OVERRIDE:")
    assert "INC-2026-001" in r.reasons[0]


# ----------------------------------------------------------------------------
# from_velocity_report
# ----------------------------------------------------------------------------

class _StubVelocityReport:
    """Minimal stand-in for ScoreVelocityReport — keeps this test file
    independent of PDS-2 internals."""

    def __init__(self, *, is_safe: bool, reasons=None, reason: str = ""):
        self.is_safe = is_safe
        if reasons is not None:
            self.reasons = reasons
        if reason:
            self.reason = reason


def test_from_velocity_report_with_reasons_tuple():
    rep = _StubVelocityReport(
        is_safe=False,
        reasons=("SCORE_DELTA_EXCEEDED", "SCORE_VELOCITY_EXCEEDED"),
    )
    refusal = from_velocity_report(
        rep, agent_wallet="agent-Z", epoch=99, detected_at=UTC_NOW,
    )
    assert refusal.gate is RefusalGate.PDS_2_SCORE_VELOCITY
    assert refusal.reasons == ("SCORE_DELTA_EXCEEDED", "SCORE_VELOCITY_EXCEEDED")
    assert refusal.requested_tier == ""  # PDS-2 is tier-agnostic


def test_from_velocity_report_with_single_reason_string():
    rep = _StubVelocityReport(is_safe=False, reason="SCORE_TIME_TRAVEL")
    refusal = from_velocity_report(
        rep, agent_wallet="agent-Z", epoch=100, detected_at=UTC_NOW,
    )
    assert refusal.reasons == ("SCORE_TIME_TRAVEL",)


def test_from_velocity_report_refuses_safe_input():
    rep = _StubVelocityReport(is_safe=True, reasons=())
    with pytest.raises(ValueError, match="safe ScoreVelocityReport"):
        from_velocity_report(
            rep, agent_wallet="agent-Z", epoch=100, detected_at=UTC_NOW,
        )
