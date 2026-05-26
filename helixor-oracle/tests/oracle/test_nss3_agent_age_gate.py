"""
tests/oracle/test_nss3_agent_age_gate.py — NSS-3 agent-registration-age
floor for GREEN-band cert issuance.

Pins:
  - Constants (MIN_AGENT_AGE_SECONDS_FOR_GREEN = 14 days,
    MIN_AGENT_AGE_EPOCHS_FOR_GREEN = 168, GATED_TIER_GREEN = "GREEN").
  - Aged wallet (>= 14 days, >= 168 epochs) is permitted GREEN.
  - Fresh wallet (< 14 days) refused GREEN with both seconds- and
    epochs-too-young reason codes.
  - Wallet that meets the seconds floor but not the epochs floor (slow
    cadence) is refused — both floors must be satisfied.
  - Wallet that meets the epochs floor but not the seconds floor (fast
    cadence) is refused — same reason.
  - YELLOW and RED requests pass at every age (NSS-3 only gates GREEN).
  - Time-travel registration (future timestamp) refused with the
    AGENT_REGISTERED_IN_FUTURE reason and age fields clamped to 0.
  - Tier-string normalisation: lowercase / whitespace inputs are
    canonicalised before the floor check.
  - Enforcement wrapper raises InsufficientAgentAgeError with the
    report attached on refusal; returns the report on the allow path.
  - Audit-scenario: a state-controlled wallet registered 1 hour ago
    is refused for GREEN — Scenario B step 4 caught.
"""

from __future__ import annotations

import pytest

from oracle.agent_age_gate import (
    GATED_TIER_GREEN,
    MIN_AGENT_AGE_EPOCHS_FOR_GREEN,
    MIN_AGENT_AGE_SECONDS_FOR_GREEN,
    REASON_EPOCHS_TOO_YOUNG,
    REASON_SECONDS_TOO_YOUNG,
    REASON_TIME_TRAVEL,
    AgentAgeContext,
    InsufficientAgentAgeError,
    enforce_agent_age_for_tier,
    verify_agent_age_for_tier,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    # 14-day / 168-epoch floor is load-bearing — any reduction must be
    # accompanied by a re-evaluation of Scenario B step 4 visibility.
    assert MIN_AGENT_AGE_SECONDS_FOR_GREEN == 14 * 24 * 3600
    assert MIN_AGENT_AGE_EPOCHS_FOR_GREEN == 168
    assert GATED_TIER_GREEN == "GREEN"


# ---------------------------------------------------------------------------
# Healthy path — aged wallet receives GREEN
# ---------------------------------------------------------------------------

def test_aged_wallet_green_allowed():
    ctx = AgentAgeContext(
        agent_wallet="Agent11111111111111111111111111111111111111",
        registered_at_unix=1_000_000,
        registered_at_epoch=10,
    )
    report = verify_agent_age_for_tier(
        ctx,
        current_unix=1_000_000 + MIN_AGENT_AGE_SECONDS_FOR_GREEN,
        current_epoch=10 + MIN_AGENT_AGE_EPOCHS_FOR_GREEN,
        tier="GREEN",
    )
    assert report.is_allowed
    assert report.reasons == ()
    assert report.agent_age_seconds == MIN_AGENT_AGE_SECONDS_FOR_GREEN
    assert report.agent_age_epochs == MIN_AGENT_AGE_EPOCHS_FOR_GREEN
    assert report.min_seconds_required == MIN_AGENT_AGE_SECONDS_FOR_GREEN
    assert report.min_epochs_required == MIN_AGENT_AGE_EPOCHS_FOR_GREEN


def test_well_aged_wallet_green_allowed():
    # 30 days / 360 epochs — well over the floor.
    ctx = AgentAgeContext(
        agent_wallet="AgedAgent",
        registered_at_unix=1_000_000,
        registered_at_epoch=10,
    )
    report = verify_agent_age_for_tier(
        ctx,
        current_unix=1_000_000 + 30 * 24 * 3600,
        current_epoch=10 + 360,
        tier="GREEN",
    )
    assert report.is_allowed


# ---------------------------------------------------------------------------
# Failing path — fresh wallet refused GREEN
# ---------------------------------------------------------------------------

def test_fresh_wallet_green_refused():
    # Wallet registered 1 hour ago — the Scenario B step-4 substrate.
    ctx = AgentAgeContext(
        agent_wallet="FreshNationStateAgent",
        registered_at_unix=1_000_000,
        registered_at_epoch=10,
    )
    report = verify_agent_age_for_tier(
        ctx,
        current_unix=1_000_000 + 3600,
        current_epoch=10 + 1,
        tier="GREEN",
    )
    assert not report.is_allowed
    assert REASON_SECONDS_TOO_YOUNG in report.reasons
    assert REASON_EPOCHS_TOO_YOUNG in report.reasons
    assert report.agent_age_seconds == 3600
    assert report.agent_age_epochs == 1


def test_seconds_floor_met_but_epochs_floor_not_refused():
    # 14 days has passed in wall-clock but only 100 epochs — a cluster
    # running slower than the canonical 2h cadence cannot mint GREEN
    # for a wallet that hasn't accumulated enough EPOCHS of data.
    ctx = AgentAgeContext(
        agent_wallet="SlowCadenceAgent",
        registered_at_unix=1_000_000,
        registered_at_epoch=10,
    )
    report = verify_agent_age_for_tier(
        ctx,
        current_unix=1_000_000 + MIN_AGENT_AGE_SECONDS_FOR_GREEN,
        current_epoch=10 + 100,
        tier="GREEN",
    )
    assert not report.is_allowed
    assert REASON_SECONDS_TOO_YOUNG not in report.reasons
    assert REASON_EPOCHS_TOO_YOUNG in report.reasons


def test_epochs_floor_met_but_seconds_floor_not_refused():
    # 168 epochs have passed but only 1 day in wall-clock — a cluster
    # running faster than the canonical 2h cadence cannot mint GREEN
    # for a wallet that hasn't aged enough in real-world time.
    ctx = AgentAgeContext(
        agent_wallet="FastCadenceAgent",
        registered_at_unix=1_000_000,
        registered_at_epoch=10,
    )
    report = verify_agent_age_for_tier(
        ctx,
        current_unix=1_000_000 + 24 * 3600,
        current_epoch=10 + MIN_AGENT_AGE_EPOCHS_FOR_GREEN,
        tier="GREEN",
    )
    assert not report.is_allowed
    assert REASON_SECONDS_TOO_YOUNG in report.reasons
    assert REASON_EPOCHS_TOO_YOUNG not in report.reasons


# ---------------------------------------------------------------------------
# Non-GREEN tiers are never gated
# ---------------------------------------------------------------------------

def test_fresh_wallet_yellow_allowed():
    ctx = AgentAgeContext(
        agent_wallet="FreshAgent",
        registered_at_unix=1_000_000,
        registered_at_epoch=10,
    )
    report = verify_agent_age_for_tier(
        ctx,
        current_unix=1_000_000 + 60,
        current_epoch=10,
        tier="YELLOW",
    )
    assert report.is_allowed
    assert report.min_seconds_required == 0
    assert report.min_epochs_required == 0


def test_fresh_wallet_red_allowed():
    ctx = AgentAgeContext(
        agent_wallet="FreshAgent",
        registered_at_unix=1_000_000,
        registered_at_epoch=10,
    )
    report = verify_agent_age_for_tier(
        ctx,
        current_unix=1_000_000 + 60,
        current_epoch=10,
        tier="RED",
    )
    assert report.is_allowed


def test_tier_normalisation_lowercase_and_whitespace():
    # "  green  " is canonicalised before the gate fires.
    ctx = AgentAgeContext(
        agent_wallet="FreshAgent",
        registered_at_unix=1_000_000,
        registered_at_epoch=10,
    )
    report = verify_agent_age_for_tier(
        ctx,
        current_unix=1_000_000 + 60,
        current_epoch=10,
        tier="  green  ",
    )
    assert not report.is_allowed
    assert report.tier_requested == "GREEN"


# ---------------------------------------------------------------------------
# Time-travel defense
# ---------------------------------------------------------------------------

def test_future_registration_refused_with_clamp():
    # Registration timestamp is AFTER current — structurally suspect.
    ctx = AgentAgeContext(
        agent_wallet="TimeTravelAgent",
        registered_at_unix=2_000_000,
        registered_at_epoch=20,
    )
    report = verify_agent_age_for_tier(
        ctx,
        current_unix=1_000_000,
        current_epoch=10,
        tier="GREEN",
    )
    assert not report.is_allowed
    assert REASON_TIME_TRAVEL in report.reasons
    # Age fields clamped to 0 so downstream telemetry stays sane.
    assert report.agent_age_seconds == 0
    assert report.agent_age_epochs == 0


def test_future_registration_blocks_yellow_too():
    # Even YELLOW/RED carry the time-travel reason — it's a structural
    # failure, not just a GREEN-gate failure.
    ctx = AgentAgeContext(
        agent_wallet="TimeTravelAgent",
        registered_at_unix=2_000_000,
        registered_at_epoch=20,
    )
    report = verify_agent_age_for_tier(
        ctx,
        current_unix=1_000_000,
        current_epoch=10,
        tier="YELLOW",
    )
    # YELLOW itself is not gated, but the time-travel reason is still
    # appended — so the report fails the allow check.
    assert REASON_TIME_TRAVEL in report.reasons
    assert not report.is_allowed


# ---------------------------------------------------------------------------
# Enforcement wrapper
# ---------------------------------------------------------------------------

def test_enforce_raises_on_fresh_wallet_green():
    ctx = AgentAgeContext(
        agent_wallet="FreshAgent",
        registered_at_unix=1_000_000,
        registered_at_epoch=10,
    )
    with pytest.raises(InsufficientAgentAgeError) as excinfo:
        enforce_agent_age_for_tier(
            ctx,
            current_unix=1_000_000 + 3600,
            current_epoch=10 + 1,
            tier="GREEN",
        )
    assert excinfo.value.report.tier_requested == "GREEN"
    assert REASON_SECONDS_TOO_YOUNG in excinfo.value.report.reasons
    assert "NSS-3" in str(excinfo.value)


def test_enforce_returns_report_on_aged_wallet():
    ctx = AgentAgeContext(
        agent_wallet="AgedAgent",
        registered_at_unix=1_000_000,
        registered_at_epoch=10,
    )
    report = enforce_agent_age_for_tier(
        ctx,
        current_unix=1_000_000 + MIN_AGENT_AGE_SECONDS_FOR_GREEN,
        current_epoch=10 + MIN_AGENT_AGE_EPOCHS_FOR_GREEN,
        tier="GREEN",
    )
    assert report.is_allowed


def test_enforce_passes_yellow_on_fresh_wallet():
    ctx = AgentAgeContext(
        agent_wallet="FreshAgent",
        registered_at_unix=1_000_000,
        registered_at_epoch=10,
    )
    report = enforce_agent_age_for_tier(
        ctx,
        current_unix=1_000_000 + 60,
        current_epoch=10,
        tier="YELLOW",
    )
    assert report.is_allowed


# ---------------------------------------------------------------------------
# Audit scenario — the exact attack the gate exists for
# ---------------------------------------------------------------------------

def test_audit_scenario_b_step4_caught():
    # Scenario B step 4: "nation-state holds 3 oracle keys and uses
    # them to issue GREEN certs for state-controlled AI agents." The
    # state-controlled agent registered moments before the cert
    # request — even with K=3 captured cluster keys, NSS-3 refuses to
    # stamp GREEN on a wallet with no on-chain history.
    state_agent = AgentAgeContext(
        agent_wallet="StateControlledFreshAgent11111111111111111111",
        registered_at_unix=1_700_000_000,
        registered_at_epoch=8400,
    )
    with pytest.raises(InsufficientAgentAgeError) as excinfo:
        enforce_agent_age_for_tier(
            state_agent,
            current_unix=1_700_000_000 + 3600,  # 1 hour after registration
            current_epoch=8400 + 1,
            tier="GREEN",
        )
    report = excinfo.value.report
    assert report.tier_requested == "GREEN"
    assert REASON_SECONDS_TOO_YOUNG in report.reasons
    assert REASON_EPOCHS_TOO_YOUNG in report.reasons
    assert report.agent_age_seconds == 3600
    assert report.agent_age_epochs == 1
    # The verdict tells the cluster operator exactly which wallet it
    # refused and what the floors are.
    assert state_agent.agent_wallet in str(excinfo.value)
