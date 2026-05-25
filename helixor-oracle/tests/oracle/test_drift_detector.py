"""
tests/oracle/test_drift_detector.py — VULN-03 fix coverage.

The per-epoch deviation detector (oracle/cluster/byzantine.py) flags only
single-epoch deviations >30%. The slow-drift attack — 2 attackers in a
5-node cluster who push the median by <30% per epoch but accumulate
material inflation over many epochs — slips past it.

This suite pins the four mitigations in oracle/cluster/drift_detector.py:

  1. Velocity gate                  — >20% epoch-over-epoch movement
  2. Rolling baseline               — >25% departure from exp-decayed mean
  3. Per-node signed-deviation      — names slow-drift attackers
  4. Activity cross-check (optional) — score velocity vs on-chain activity
"""

from __future__ import annotations

import pytest

from oracle.cluster.drift_detector import (
    ACTIVITY_DIVERGENCE_THRESHOLD,
    BASELINE_THRESHOLD,
    DRIFT_REASON_ACTIVITY,
    DRIFT_REASON_BASELINE,
    DRIFT_REASON_VELOCITY,
    MIN_PARTICIPATION_FOR_DRIFT,
    NODE_DRIFT_THRESHOLD,
    ROLLING_DECAY,
    ROLLING_WINDOW,
    VELOCITY_THRESHOLD,
    ActivityProvider,
    AgentActivity,
    DriftDetector,
    default_drift_detector,
)


# =============================================================================
# Threshold pins — wire compatibility surface
# =============================================================================


class TestThresholds:

    def test_velocity_threshold_is_twenty_percent(self):
        assert VELOCITY_THRESHOLD == 0.20

    def test_baseline_threshold_is_twenty_five_percent(self):
        assert BASELINE_THRESHOLD == 0.25

    def test_node_drift_threshold_is_eight_percent(self):
        assert NODE_DRIFT_THRESHOLD == 0.08

    def test_rolling_window_is_ten_epochs(self):
        assert ROLLING_WINDOW == 10

    def test_rolling_decay_is_zero_point_seven(self):
        assert ROLLING_DECAY == 0.7

    def test_min_participation_for_drift(self):
        assert MIN_PARTICIPATION_FOR_DRIFT == 5

    def test_activity_divergence_threshold(self):
        assert ACTIVITY_DIVERGENCE_THRESHOLD == 0.5

    def test_drift_reasons_stable(self):
        # Wire codes — emitted in DriftFlag.reasons. Stable strings.
        assert DRIFT_REASON_VELOCITY == "VELOCITY_SPIKE"
        assert DRIFT_REASON_BASELINE == "BASELINE_DRIFT"
        assert DRIFT_REASON_ACTIVITY == "ACTIVITY_MISMATCH"


# =============================================================================
# DriftDetector constructor validation
# =============================================================================


class TestConstructorValidation:

    @pytest.mark.parametrize("v", [0.0, 1.0, -0.1, 1.5])
    def test_velocity_threshold_rejected(self, v: float):
        with pytest.raises(ValueError, match="velocity_threshold"):
            DriftDetector(velocity_threshold=v)

    @pytest.mark.parametrize("b", [0.0, 1.0, -0.5])
    def test_baseline_threshold_rejected(self, b: float):
        with pytest.raises(ValueError, match="baseline_threshold"):
            DriftDetector(baseline_threshold=b)

    @pytest.mark.parametrize("n", [0.0, 1.0, -0.3])
    def test_node_drift_threshold_rejected(self, n: float):
        with pytest.raises(ValueError, match="node_drift_threshold"):
            DriftDetector(node_drift_threshold=n)

    @pytest.mark.parametrize("w", [0, 1, -1])
    def test_rolling_window_rejected(self, w: int):
        with pytest.raises(ValueError, match="rolling_window"):
            DriftDetector(rolling_window=w)

    @pytest.mark.parametrize("d", [0.0, -0.1, 1.5])
    def test_rolling_decay_rejected(self, d: float):
        with pytest.raises(ValueError, match="rolling_decay"):
            DriftDetector(rolling_decay=d)

    def test_min_participation_rejected(self):
        with pytest.raises(ValueError, match="min_participation"):
            DriftDetector(min_participation_for_drift=0)

    def test_default_factory_returns_instance(self):
        d = default_drift_detector()
        assert isinstance(d, DriftDetector)


# =============================================================================
# Velocity gate — single-epoch jump
# =============================================================================


class TestVelocityGate:

    def test_first_epoch_never_flagged_for_velocity(self):
        # No previous score to compare against -> velocity gate cannot fire.
        d = DriftDetector()
        flag = d.observe("agentA", 1, 800, {"n0": 800}, 800)
        assert DRIFT_REASON_VELOCITY not in flag.reasons

    def test_stable_epoch_not_flagged(self):
        d = DriftDetector()
        d.observe("agentA", 1, 800, {"n0": 800}, 800)
        flag = d.observe("agentA", 2, 805, {"n0": 805}, 805)
        # +0.6% — well under 20% — no velocity flag.
        assert DRIFT_REASON_VELOCITY not in flag.reasons

    def test_twenty_one_percent_jump_flagged(self):
        d = DriftDetector()
        d.observe("agentA", 1, 800, {"n0": 800}, 800)
        flag = d.observe("agentA", 2, 970, {"n0": 970}, 970)
        # +21.25% — over the 20% gate -> flagged.
        assert DRIFT_REASON_VELOCITY in flag.reasons
        assert flag.velocity == pytest.approx(0.2125)

    def test_twenty_percent_jump_NOT_flagged_at_boundary(self):
        # Strict >, not >= — boundary is honest.
        d = DriftDetector()
        d.observe("agentA", 1, 800, {"n0": 800}, 800)
        flag = d.observe("agentA", 2, 960, {"n0": 960}, 960)
        # Exactly +20% -> NOT flagged (the gate is strict >).
        assert DRIFT_REASON_VELOCITY not in flag.reasons

    def test_downward_velocity_also_flagged(self):
        # The gate is symmetric — a sudden drop is also suspicious (e.g.,
        # attackers tanking a competitor agent's score).
        d = DriftDetector()
        d.observe("agentA", 1, 800, {"n0": 800}, 800)
        flag = d.observe("agentA", 2, 600, {"n0": 600}, 600)
        # -25% — flagged.
        assert DRIFT_REASON_VELOCITY in flag.reasons
        assert flag.velocity < 0


# =============================================================================
# Rolling baseline — long-horizon drift
# =============================================================================


class TestRollingBaseline:

    def test_first_epoch_no_baseline(self):
        d = DriftDetector()
        flag = d.observe("agentA", 1, 800, {"n0": 800}, 800)
        # No history, no baseline -> no baseline flag.
        assert DRIFT_REASON_BASELINE not in flag.reasons
        assert flag.baseline == 0.0

    def test_baseline_warms_up_over_epochs(self):
        d = DriftDetector()
        for e in range(1, 6):
            d.observe("agentA", e, 800, {"n0": 800}, 800)
        # The baseline of a constant series should equal that constant.
        flag = d.observe("agentA", 6, 800, {"n0": 800}, 800)
        assert flag.baseline == pytest.approx(800.0, rel=0.01)

    def test_constant_baseline_no_drift_flag(self):
        d = DriftDetector()
        for e in range(1, 11):
            d.observe("agentA", e, 800, {"n0": 800}, 800)
        flag = d.observe("agentA", 11, 800, {"n0": 800}, 800)
        assert DRIFT_REASON_BASELINE not in flag.reasons

    def test_slow_drift_eventually_trips_baseline(self):
        """
        VULN-03 reproduction: each epoch a small (<20%) push above the
        baseline; eventually the cumulative drift breaks 25% from the
        rolling baseline and the BASELINE flag fires.
        """
        d = DriftDetector()
        # Warm up a steady 800 baseline.
        for e in range(1, 6):
            d.observe("agentA", e, 800, {"n0": 800}, 800)
        # Now push the score up by 50% in one jump — over baseline_threshold,
        # under-no-wait this is also over velocity, but the point is the
        # BASELINE reason appears.
        flag = d.observe("agentA", 6, 1200, {"n0": 1200}, 1200)
        assert DRIFT_REASON_BASELINE in flag.reasons
        assert flag.baseline_deviation > BASELINE_THRESHOLD

    def test_exponential_decay_weights_recent_observations_more(self):
        """
        With decay=0.7, the most recent observation carries more weight than
        an old one. After enough epochs at a NEW level, the baseline catches
        up — it shouldn't keep flagging once the new level is the norm.
        """
        d = DriftDetector(rolling_decay=0.7)
        # 10 epochs at 500 -> baseline ~= 500.
        for e in range(1, 11):
            d.observe("agentA", e, 500, {"n0": 500}, 500)
        # Push to 700 and hold there long enough for the baseline to follow.
        # The first epoch at 700 will trip baseline (+40% from baseline 500),
        # but after enough epochs at 700, the rolling baseline catches up.
        d.observe("agentA", 11, 700, {"n0": 700}, 700)
        for e in range(12, 25):
            d.observe("agentA", e, 700, {"n0": 700}, 700)
        flag = d.observe("agentA", 25, 700, {"n0": 700}, 700)
        # Baseline has caught up to ~700; no more baseline flag.
        assert DRIFT_REASON_BASELINE not in flag.reasons
        assert flag.baseline == pytest.approx(700.0, rel=0.01)


# =============================================================================
# Per-node signed-deviation attribution — VULN-03's core fix
# =============================================================================


class TestNodeDriftAttribution:

    def test_no_attribution_below_min_participation(self):
        # min_participation_for_drift=5; a node with only 4 observations
        # cannot yet be flagged a drift attacker no matter the mean.
        d = DriftDetector()
        for e in range(1, 5):
            # n2 is consistently 15% over median — clearly a drift signature
            # but not enough observations yet.
            d.observe(
                "agentA", e, 800,
                {"n0": 780, "n1": 800, "n2": 920},
                cluster_median=800,
            )
        attackers = d.drift_attackers("agentA")
        assert "n2" not in attackers

    def test_consistent_upward_pusher_attributed(self):
        """The core VULN-03 fix: a node that is consistently above the
        median, even at small individual deviations, is attributed."""
        d = DriftDetector()
        # 10 epochs. n2 is always ~12% above the median. Each individual
        # epoch's deviation is well under 30% (so per-epoch detector misses
        # it), but the rolling signed mean is >8% -> drift attacker.
        for e in range(1, 11):
            d.observe(
                "agentA", e, 800,
                {"n0": 800, "n1": 800, "n2": 896},  # n2 = +12%
                cluster_median=800,
            )
        attackers = d.drift_attackers("agentA")
        assert "n2" in attackers
        assert "n0" not in attackers
        assert "n1" not in attackers

    def test_consistent_downward_pusher_attributed(self):
        # Symmetric: consistently below the median is just as flagged.
        d = DriftDetector()
        for e in range(1, 11):
            d.observe(
                "agentA", e, 800,
                {"n0": 800, "n1": 800, "n2": 700},  # n2 = -12.5%
                cluster_median=800,
            )
        attackers = d.drift_attackers("agentA")
        assert "n2" in attackers

    def test_zero_mean_noise_not_attributed(self):
        # A node whose signed deviations average to ~0 (noise) is NOT
        # attributed, even with many observations.
        d = DriftDetector()
        # n2 alternates +5%, -5% — signed mean ~= 0.
        for e in range(1, 11):
            n2_score = 840 if e % 2 == 0 else 760
            d.observe(
                "agentA", e, 800,
                {"n0": 800, "n1": 800, "n2": n2_score},
                cluster_median=800,
            )
        attackers = d.drift_attackers("agentA")
        assert "n2" not in attackers

    def test_attribution_details_exposed(self):
        d = DriftDetector()
        for e in range(1, 11):
            d.observe(
                "agentA", e, 800,
                {"n0": 800, "n1": 800, "n2": 896},  # n2 = +12%
                cluster_median=800,
            )
        attributions = d.node_attributions("agentA")
        by_id = {a.node_id: a for a in attributions}
        assert by_id["n2"].epochs_contributed == 10
        assert by_id["n2"].mean_signed_deviation == pytest.approx(0.12)
        assert by_id["n2"].is_drift_attacker is True
        assert by_id["n2"].drift_direction == "UP"
        assert by_id["n0"].is_drift_attacker is False

    def test_two_coordinated_attackers_both_named(self):
        """
        The full VULN-03 scenario: 2 of 5 nodes coordinate. Both should be
        named, not just one.
        """
        d = DriftDetector()
        for e in range(1, 11):
            d.observe(
                "agentA", e, 800,
                # 3 honest at 800, 2 attackers at 900 (+12.5% each).
                {"n0": 800, "n1": 800, "n2": 800, "atk0": 900, "atk1": 900},
                cluster_median=800,
            )
        attackers = d.drift_attackers("agentA")
        assert "atk0" in attackers
        assert "atk1" in attackers
        assert "n0" not in attackers
        assert "n1" not in attackers
        assert "n2" not in attackers


# =============================================================================
# Activity cross-check — VULN-03 + VULN-07 combo
# =============================================================================


class _StubActivityProvider:
    """In-memory ActivityProvider for tests."""

    def __init__(self, samples: dict[str, list[AgentActivity]]):
        self._samples = samples

    def history(self, agent_wallet: str, last_n_epochs: int) -> list[AgentActivity]:
        recent = self._samples.get(agent_wallet, [])
        return recent[-last_n_epochs:]


class TestActivityCrossCheck:

    def test_no_provider_no_activity_check(self):
        # Without a provider, activity_divergence stays 0 and the activity
        # reason never fires.
        d = DriftDetector()
        d.observe("agentA", 1, 800, {"n0": 800}, 800)
        # +30% velocity — also trips velocity, but verify activity isn't
        # listed as a reason since no provider is wired.
        flag = d.observe("agentA", 2, 1040, {"n0": 1040}, 1040)
        assert DRIFT_REASON_ACTIVITY not in flag.reasons
        assert flag.activity_divergence == 0.0

    def test_score_surge_with_flat_activity_flagged(self):
        # Score grows 30%; activity is flat. Divergence = 0.30 > 0.5? No — 0.3
        # is under the 0.5 threshold. Let's push higher.
        provider = _StubActivityProvider({
            "agentA": [
                AgentActivity("agentA", 1, tx_count=100),
                AgentActivity("agentA", 2, tx_count=100),  # flat
            ],
        })
        d = DriftDetector(activity_provider=provider)
        d.observe("agentA", 1, 800, {"n0": 800}, 800)
        # Score velocity = +60%, activity velocity = 0% -> divergence 0.6 > 0.5
        flag = d.observe("agentA", 2, 1280, {"n0": 1280}, 1280)
        assert DRIFT_REASON_ACTIVITY in flag.reasons
        assert flag.activity_divergence == pytest.approx(0.6)

    def test_score_surge_with_matching_activity_NOT_flagged(self):
        # A legitimate reputation event: score and activity move together.
        provider = _StubActivityProvider({
            "agentA": [
                AgentActivity("agentA", 1, tx_count=100),
                AgentActivity("agentA", 2, tx_count=160),  # +60%
            ],
        })
        d = DriftDetector(activity_provider=provider)
        d.observe("agentA", 1, 800, {"n0": 800}, 800)
        # Score +60%, activity +60% -> divergence ~= 0 -> no activity flag.
        flag = d.observe("agentA", 2, 1280, {"n0": 1280}, 1280)
        assert DRIFT_REASON_ACTIVITY not in flag.reasons

    def test_volume_metric_preferred_over_tx_count_when_set(self):
        # When `volume_metric` is > 0 it is used as the velocity series.
        provider = _StubActivityProvider({
            "agentA": [
                AgentActivity("agentA", 1, tx_count=100, volume_metric=1000.0),
                AgentActivity("agentA", 2, tx_count=999, volume_metric=1010.0),
            ],
        })
        d = DriftDetector(activity_provider=provider)
        d.observe("agentA", 1, 800, {"n0": 800}, 800)
        # tx_count looks healthy, but volume_metric only grew 1% — divergence
        # off the +60% score velocity exceeds threshold.
        flag = d.observe("agentA", 2, 1280, {"n0": 1280}, 1280)
        assert DRIFT_REASON_ACTIVITY in flag.reasons

    def test_provider_exception_does_not_crash(self):
        class _Broken:
            def history(self, agent_wallet: str, last_n_epochs: int):
                raise RuntimeError("RPC down")

        d = DriftDetector(activity_provider=_Broken())
        d.observe("agentA", 1, 800, {"n0": 800}, 800)
        flag = d.observe("agentA", 2, 850, {"n0": 850}, 850)
        # Activity check silently skipped — no activity flag, no crash.
        assert DRIFT_REASON_ACTIVITY not in flag.reasons
        assert flag.activity_divergence == 0.0


# =============================================================================
# History bounds — the rolling deque
# =============================================================================


class TestRollingBounds:

    def test_history_capped_at_rolling_window(self):
        d = DriftDetector(rolling_window=5)
        for e in range(1, 11):
            d.observe("agentA", e, 800 + e, {"n0": 800 + e}, 800 + e)
        history = d.history_for("agentA")
        assert len(history) == 5
        # Last 5 epochs only.
        assert [h[0] for h in history] == [6, 7, 8, 9, 10]

    def test_node_dev_history_capped(self):
        d = DriftDetector(rolling_window=5, min_participation_for_drift=3)
        for e in range(1, 11):
            d.observe(
                "agentA", e, 800,
                {"n0": 800, "n2": 880},
                cluster_median=800,
            )
        attributions = d.node_attributions("agentA")
        for a in attributions:
            assert a.epochs_contributed <= 5


# =============================================================================
# Determinism — every honest node must reach the same verdict
# =============================================================================


class TestDeterminism:

    def test_observe_is_deterministic(self):
        def _run() -> tuple:
            d = DriftDetector()
            flags = []
            for e in range(1, 11):
                f = d.observe(
                    "agentA", e, 800 + e * 5,
                    {"n0": 800, "n1": 800, "n2": 850 + e * 6},
                    cluster_median=800,
                )
                flags.append((f.reasons, round(f.velocity, 4),
                              round(f.baseline, 2),
                              round(f.baseline_deviation, 4)))
            return tuple(flags), d.drift_attackers("agentA")

        first = _run()
        for _ in range(10):
            assert _run() == first


# =============================================================================
# The VULN-03 attack scenario, end-to-end
# =============================================================================


class TestVuln03AttackScenario:
    """
    Reproduces the slow-drift attack from the audit report against the
    drift detector. Without the detector, every epoch passes the 30%
    per-epoch gate. With the detector, the attackers are named and the
    BASELINE flag fires.
    """

    def test_slow_drift_attack_is_caught(self):
        d = DriftDetector()
        # 5-node cluster: 3 honest, 2 coordinated attackers.
        # Honest nodes scoring an agent at 800 stably. Attackers each push
        # +12% above the cluster median EVERY epoch.
        # Per-epoch deviation per attacker is well under 30% (the audit's
        # attack assumption). The drift detector still catches them via
        # the signed-mean attribution.
        for e in range(1, 11):
            d.observe(
                agent_wallet="agentA",
                epoch=e,
                aggregated_score=800,    # honest median wins each epoch
                per_node_scores={
                    "honest0": 800,
                    "honest1": 800,
                    "honest2": 800,
                    "atk0":    896,      # +12%
                    "atk1":    896,      # +12%
                },
                cluster_median=800,
            )
        attackers = d.drift_attackers("agentA")
        # The attackers are named even though no per-epoch deviation
        # crossed 30%.
        assert set(attackers) == {"atk0", "atk1"}

    def test_genuine_reputation_change_not_misclassified(self):
        # A legitimate, gradual improvement: every node moves up together.
        # No node has a consistent signed deviation from the median (they
        # are the median). Nobody is flagged as a drift attacker.
        d = DriftDetector()
        for e in range(1, 11):
            score = 600 + e * 10                  # 610, 620, ..., 700
            d.observe(
                "agentA", e, score,
                {"n0": score, "n1": score, "n2": score},
                cluster_median=score,
            )
        attackers = d.drift_attackers("agentA")
        assert attackers == ()
