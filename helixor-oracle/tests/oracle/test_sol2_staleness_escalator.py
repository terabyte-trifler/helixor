"""
tests/oracle/test_sol2_staleness_escalator.py — SOL-2 per-agent
age-based tier degradation escalator.

Pins:
  - Constants (GREEN_TO_YELLOW=6h, YELLOW_TO_RED=12h, REFUSE=24h,
    future-skew tolerance=60s).
  - Fresh GREEN cert keeps GREEN.
  - GREEN cert at 7h is downgraded to YELLOW.
  - YELLOW cert at 13h is downgraded to RED.
  - GREEN cert at 13h is downgraded to RED (transitive: GREEN->YELLOW->RED).
  - Any cert older than 24h is REFUSED.
  - YELLOW input never upgrades to GREEN regardless of age.
  - RED input stays RED until REFUSE.
  - Future-dated cert is REFUSED with time-travel reason.
  - Small clock skew (< 60s) tolerated; age clamps to 0.
  - Tier-string normalisation: " green " is accepted as GREEN.
  - Audit-scenario: a 12-hour-old GREEN cert on a degrading agent is
    downgraded to YELLOW + flagged so the consumer cannot extend a new
    loan at GREEN trust level.
"""

from __future__ import annotations

from oracle.staleness_escalator import (
    ESCALATOR_FUTURE_TOLERANCE_SECONDS,
    GREEN_TO_YELLOW_AFTER_SECONDS,
    REASON_AGE_DOWNGRADE_GREEN_TO_YELLOW,
    REASON_AGE_DOWNGRADE_YELLOW_TO_RED,
    REASON_AGE_REFUSE,
    REASON_ESCALATOR_TIME_TRAVEL,
    REFUSE_AFTER_SECONDS,
    TIER_GREEN,
    TIER_RED,
    TIER_REFUSE,
    TIER_YELLOW,
    YELLOW_TO_RED_AFTER_SECONDS,
    CertSnapshot,
    escalate_for_age,
)


NOW = 1_700_000_000


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert GREEN_TO_YELLOW_AFTER_SECONDS == 6 * 3600
    assert YELLOW_TO_RED_AFTER_SECONDS == 12 * 3600
    assert REFUSE_AFTER_SECONDS == 24 * 3600
    assert ESCALATOR_FUTURE_TOLERANCE_SECONDS == 60


# ---------------------------------------------------------------------------
# Healthy paths — no escalation
# ---------------------------------------------------------------------------

def test_fresh_green_kept_green():
    snap = CertSnapshot("AgentA", TIER_GREEN, NOW - 60)
    report = escalate_for_age(snap, current_unix=NOW)
    assert report.effective_tier == TIER_GREEN
    assert not report.was_downgraded
    assert report.reasons == ()


def test_green_at_boundary_kept_green():
    # Inclusive boundary: exactly 6h is still GREEN.
    snap = CertSnapshot("AgentA", TIER_GREEN, NOW - GREEN_TO_YELLOW_AFTER_SECONDS)
    report = escalate_for_age(snap, current_unix=NOW)
    assert report.effective_tier == TIER_GREEN


def test_fresh_yellow_kept_yellow():
    snap = CertSnapshot("AgentA", TIER_YELLOW, NOW - 60)
    report = escalate_for_age(snap, current_unix=NOW)
    assert report.effective_tier == TIER_YELLOW


def test_fresh_red_kept_red():
    snap = CertSnapshot("AgentA", TIER_RED, NOW - 60)
    report = escalate_for_age(snap, current_unix=NOW)
    assert report.effective_tier == TIER_RED


# ---------------------------------------------------------------------------
# Downgrade paths
# ---------------------------------------------------------------------------

def test_green_at_7h_downgraded_to_yellow():
    snap = CertSnapshot("AgentA", TIER_GREEN, NOW - (7 * 3600))
    report = escalate_for_age(snap, current_unix=NOW)
    assert report.effective_tier == TIER_YELLOW
    assert REASON_AGE_DOWNGRADE_GREEN_TO_YELLOW in report.reasons
    assert report.was_downgraded


def test_yellow_at_13h_downgraded_to_red():
    snap = CertSnapshot("AgentA", TIER_YELLOW, NOW - (13 * 3600))
    report = escalate_for_age(snap, current_unix=NOW)
    assert report.effective_tier == TIER_RED
    assert REASON_AGE_DOWNGRADE_YELLOW_TO_RED in report.reasons


def test_green_at_13h_transitively_downgraded_to_red():
    # GREEN -> YELLOW (past 6h) -> RED (past 12h). Both reasons fire.
    snap = CertSnapshot("AgentA", TIER_GREEN, NOW - (13 * 3600))
    report = escalate_for_age(snap, current_unix=NOW)
    assert report.effective_tier == TIER_RED
    assert REASON_AGE_DOWNGRADE_GREEN_TO_YELLOW in report.reasons
    assert REASON_AGE_DOWNGRADE_YELLOW_TO_RED in report.reasons


def test_yellow_at_7h_kept_yellow():
    # 7h on YELLOW input is NOT past the YELLOW->RED floor (12h);
    # YELLOW input doesn't trigger GREEN->YELLOW either since the
    # downgrade only applies when the issued tier is GREEN.
    snap = CertSnapshot("AgentA", TIER_YELLOW, NOW - (7 * 3600))
    report = escalate_for_age(snap, current_unix=NOW)
    assert report.effective_tier == TIER_YELLOW
    assert report.reasons == ()


def test_red_input_never_upgraded():
    # RED cert at 1 hour stays RED — no upgrade path exists.
    snap = CertSnapshot("AgentA", TIER_RED, NOW - 3600)
    report = escalate_for_age(snap, current_unix=NOW)
    assert report.effective_tier == TIER_RED


# ---------------------------------------------------------------------------
# REFUSE path
# ---------------------------------------------------------------------------

def test_any_cert_past_24h_refused():
    for tier in (TIER_GREEN, TIER_YELLOW, TIER_RED):
        snap = CertSnapshot("AgentA", tier, NOW - (25 * 3600))
        report = escalate_for_age(snap, current_unix=NOW)
        assert report.effective_tier == TIER_REFUSE, tier
        assert REASON_AGE_REFUSE in report.reasons
        assert report.is_refused


def test_at_refuse_boundary_still_acted_on():
    # Inclusive boundary: exactly 24h is NOT refused.
    snap = CertSnapshot("AgentA", TIER_YELLOW, NOW - REFUSE_AFTER_SECONDS)
    report = escalate_for_age(snap, current_unix=NOW)
    assert report.effective_tier != TIER_REFUSE


# ---------------------------------------------------------------------------
# Time-travel defense
# ---------------------------------------------------------------------------

def test_future_cert_refused():
    snap = CertSnapshot("AgentA", TIER_GREEN, NOW + 600)
    report = escalate_for_age(snap, current_unix=NOW)
    assert report.effective_tier == TIER_REFUSE
    assert REASON_ESCALATOR_TIME_TRAVEL in report.reasons


def test_small_skew_within_tolerance_kept_green():
    snap = CertSnapshot("AgentA", TIER_GREEN, NOW + 30)
    report = escalate_for_age(snap, current_unix=NOW)
    assert report.effective_tier == TIER_GREEN
    assert report.cert_age_seconds == 0


# ---------------------------------------------------------------------------
# Tier normalisation
# ---------------------------------------------------------------------------

def test_tier_string_normalisation():
    snap = CertSnapshot("AgentA", " green ", NOW - 60)
    report = escalate_for_age(snap, current_unix=NOW)
    assert report.issued_tier == TIER_GREEN
    assert report.effective_tier == TIER_GREEN


def test_tier_string_lowercase_yellow():
    snap = CertSnapshot("AgentA", "yellow", NOW - (13 * 3600))
    report = escalate_for_age(snap, current_unix=NOW)
    assert report.issued_tier == TIER_YELLOW
    assert report.effective_tier == TIER_RED


# ---------------------------------------------------------------------------
# Audit scenario — the exact attack the gate exists for
# ---------------------------------------------------------------------------

def test_audit_scenario_c_step4_caught():
    # Scenario C step 4: "agents whose behavior degrades never get
    # updated certs." 12 hours have passed since cluster issued GREEN
    # for this agent. The agent's behaviour has been deteriorating
    # behind the scenes; SOL-2 forces the consumer to TREAT the cert
    # as RED (transitively downgraded), so a new loan against this
    # agent is no longer at GREEN trust level.
    degrading_agent = CertSnapshot(
        agent_wallet="DegradingAgent111111111111111111111111111111",
        issued_tier=TIER_GREEN,
        issued_at_unix=NOW - (12 * 3600 + 60),  # 12h 1min ago
    )
    report = escalate_for_age(degrading_agent, current_unix=NOW)
    assert report.issued_tier == TIER_GREEN
    assert report.effective_tier == TIER_RED
    assert REASON_AGE_DOWNGRADE_GREEN_TO_YELLOW in report.reasons
    assert REASON_AGE_DOWNGRADE_YELLOW_TO_RED in report.reasons
    assert report.cert_age_seconds == 12 * 3600 + 60
