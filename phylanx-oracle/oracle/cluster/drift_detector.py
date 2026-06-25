"""
oracle/cluster/drift_detector.py — cross-epoch drift detection (VULN-03 fix).

PROBLEM
-------
The per-epoch deviation detector (oracle/cluster/byzantine.py) catches a node
that lies BIG in one epoch — anything >30% off the cluster median is flagged.
But it cannot catch the "slow drift" attack:

    Epoch 1:  honest median 800. Attacker submits 800.  (within 30%)
    Epoch 2:  honest median 800. Attacker submits 900.  (+12.5% — safe)
    Epoch 3:  honest median grows to ~840 (attacker pulled it).
              Attacker submits 950.  (~13% over new median — safe)
    ...
    Epoch 30: median is 950. Attacker submits 1100. Each epoch was <30%
              but the score is inflated 37% from baseline.

Each individual epoch passes the 30% gate. The damage accrues over time.

SOLUTION — THREE-LAYER CROSS-EPOCH DEFENCE
------------------------------------------
1. VELOCITY GATE. The aggregated honest score for an agent moving more than
   `VELOCITY_THRESHOLD` (20%) between consecutive epochs is flagged. A
   genuine reputation change rarely jumps that fast; a sudden surge is the
   fingerprint of coordinated manipulation.

2. ROLLING BASELINE. An exponentially-decayed baseline of each agent's
   score over the last `ROLLING_WINDOW` (10) epochs. Significant drift
   FROM the baseline — beyond `BASELINE_THRESHOLD` — is flagged even when
   no single epoch's velocity is high. This catches the slow accumulation.

3. PER-NODE DRIFT ATTRIBUTION. For each node, track the SIGNED deviation
   from the cluster median across the rolling window. A node whose mean
   signed deviation exceeds `NODE_DRIFT_THRESHOLD` (consistently above or
   below the median) is named as a slow-drift attacker — even if no
   individual deviation crossed the 30% gate.

4. ACTIVITY CROSS-CHECK (optional). If an `ActivityProvider` is wired,
   compare score velocity against on-chain transaction-volume velocity.
   A score surge without a matching activity surge is the strongest
   single-epoch signal for VULN-03 + VULN-07 (feature poisoning) combo.

DETERMINISM
-----------
All four checks are pure integer / float arithmetic over the explicit
history kept by the detector. No clock, no randomness, no I/O. Every
honest node maintains the identical detector state and reaches the
identical drift verdict.
"""

from __future__ import annotations

import logging
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol

logger = logging.getLogger("phylanx.oracle.cluster.drift")


# =============================================================================
# Thresholds — chosen with documented rationale
# =============================================================================

# Epoch-over-epoch movement of an aggregated honest score larger than this
# fraction is flagged. 20% — below the per-epoch deviation gate (30%), but
# generous enough that a legitimate reputational event (e.g. an agent
# recovering from a degradation incident) does not trip it on a single epoch.
VELOCITY_THRESHOLD = 0.20

# How many recent epochs the baseline averages over. 10 — long enough that
# a coordinated slow drift over many epochs registers as a clear departure
# from the historical norm, short enough that a genuine, gradual reputation
# change eventually becomes the new baseline.
ROLLING_WINDOW = 10

# Exponential decay weight per epoch in the rolling baseline. 0.7 — recent
# epochs weighted more than ancient ones, but with enough memory that a 5-
# epoch coordinated push cannot become "the new normal" within the window.
ROLLING_DECAY = 0.7

# Deviation from the rolling baseline larger than this fraction is flagged.
# 25% — between the per-epoch deviation gate (30%) and the velocity gate
# (20%). A score drifting 25% from its 10-epoch baseline reflects a
# sustained shift the cluster should treat as suspicious.
BASELINE_THRESHOLD = 0.25

# A node whose MEAN SIGNED deviation over the rolling window exceeds this
# fraction is flagged as a slow-drift attacker. The signed mean catches
# CONSISTENT directional pressure even when no single deviation crossed
# the 30% per-epoch gate. 8% — calibrated so a node that is, on average,
# 8% above (or below) the median over 10 epochs is suspicious; honest
# noise around the median has zero expected mean.
NODE_DRIFT_THRESHOLD = 0.08

# A node must contribute to at least this many epochs in the window before
# its signed mean is considered — prevents flagging a node that just joined
# and happened to have one extreme submission.
MIN_PARTICIPATION_FOR_DRIFT = 5

# How far off the expected activity-velocity ratio a score surge can sit
# before activity correlation flags it. 0.5 means a score growing twice
# as fast as activity (or activity falling while score climbs) is suspect.
ACTIVITY_DIVERGENCE_THRESHOLD = 0.5


# =============================================================================
# Activity provider — the on-chain cross-check hook
# =============================================================================


@dataclass(frozen=True, slots=True)
class AgentActivity:
    """A coarse activity metric for one agent in one epoch."""

    agent_wallet: str
    epoch: int
    # Total on-chain transaction count attributed to the agent this epoch.
    tx_count: int
    # Optional finer-grained metric (notional volume, unique counterparties,
    # etc.). When supplied it is used as the velocity-comparison series
    # instead of `tx_count`; left at 0.0 it is ignored.
    volume_metric: float = 0.0


class ActivityProvider(Protocol):
    """
    Provides historical agent activity for the cross-check. Production
    implementations query the RPC / indexer; tests pass an in-memory stub.

    The provider is OPTIONAL — the detector still works without it (it just
    skips the activity-correlation check).
    """

    def history(self, agent_wallet: str, last_n_epochs: int) -> list[AgentActivity]:
        ...


# =============================================================================
# Detector results
# =============================================================================


# Wire codes — stable, mirror the on-chain ProofType.SlowDrift family.
DRIFT_REASON_VELOCITY = "VELOCITY_SPIKE"
DRIFT_REASON_BASELINE = "BASELINE_DRIFT"
DRIFT_REASON_ACTIVITY = "ACTIVITY_MISMATCH"


@dataclass(frozen=True, slots=True)
class DriftFlag:
    """One epoch's drift verdict for one agent."""

    agent_wallet: str
    epoch: int
    aggregated_score: int
    reasons: tuple[str, ...]
    # The previous epoch's score (for velocity); 0 if this is the first epoch.
    previous_score: int
    # The rolling baseline at the time of evaluation; 0 if window not yet warm.
    baseline: float
    # Velocity fraction (signed). >0 means upward drift, <0 means downward.
    velocity: float
    # Deviation from baseline as a fraction (signed).
    baseline_deviation: float
    # Activity divergence (signed). Only populated if activity_provider given.
    activity_divergence: float = 0.0

    @property
    def is_flagged(self) -> bool:
        return bool(self.reasons)


@dataclass(frozen=True, slots=True)
class NodeDriftAttribution:
    """Per-node assessment of slow-drift contribution over the rolling window."""

    node_id: str
    # Number of epochs in the window this node contributed to.
    epochs_contributed: int
    # Mean signed deviation from the cluster median (positive = consistently
    # above, negative = consistently below).
    mean_signed_deviation: float
    # True if mean_signed_deviation exceeds NODE_DRIFT_THRESHOLD in absolute
    # value AND epochs_contributed >= MIN_PARTICIPATION_FOR_DRIFT.
    is_drift_attacker: bool

    @property
    def drift_direction(self) -> str:
        if self.mean_signed_deviation > 0:
            return "UP"
        if self.mean_signed_deviation < 0:
            return "DOWN"
        return "FLAT"


# =============================================================================
# The detector
# =============================================================================


# Bounded per-agent history of (epoch, aggregated_score) pairs.
_AgentHistory = deque  # values are tuple[int, int]
# Bounded per-(agent, node) history of (epoch, signed_deviation) pairs.
_NodeAgentHistory = deque  # values are tuple[int, float]


@dataclass
class _AgentState:
    """Mutable per-agent state — bounded by ROLLING_WINDOW + 1."""

    history: deque = field(default_factory=deque)
    # node_id -> rolling deque of (epoch, signed_deviation_fraction)
    node_signed_devs: dict[str, deque] = field(default_factory=dict)


class DriftDetector:
    """
    Cross-epoch drift detection. Fed one epoch's results at a time via
    `observe`, returns a `DriftFlag` for each (agent, epoch) and an
    attribution view via `node_attributions`.

    The detector is STATEFUL — it accumulates rolling history across
    epochs — but stateful in a fully-deterministic way: replaying the same
    sequence of observations yields the same flags. Every honest node
    maintains its own copy of the detector and arrives at the same
    verdicts.
    """

    def __init__(
        self,
        *,
        velocity_threshold: float = VELOCITY_THRESHOLD,
        baseline_threshold: float = BASELINE_THRESHOLD,
        node_drift_threshold: float = NODE_DRIFT_THRESHOLD,
        rolling_window: int = ROLLING_WINDOW,
        rolling_decay: float = ROLLING_DECAY,
        min_participation_for_drift: int = MIN_PARTICIPATION_FOR_DRIFT,
        activity_divergence_threshold: float = ACTIVITY_DIVERGENCE_THRESHOLD,
        activity_provider: ActivityProvider | None = None,
    ) -> None:
        if not 0.0 < velocity_threshold < 1.0:
            raise ValueError("velocity_threshold must be in (0, 1)")
        if not 0.0 < baseline_threshold < 1.0:
            raise ValueError("baseline_threshold must be in (0, 1)")
        if not 0.0 < node_drift_threshold < 1.0:
            raise ValueError("node_drift_threshold must be in (0, 1)")
        if rolling_window < 2:
            raise ValueError("rolling_window must be >= 2")
        if not 0.0 < rolling_decay <= 1.0:
            raise ValueError("rolling_decay must be in (0, 1]")
        if min_participation_for_drift < 1:
            raise ValueError("min_participation_for_drift must be >= 1")

        self._velocity_threshold = velocity_threshold
        self._baseline_threshold = baseline_threshold
        self._node_drift_threshold = node_drift_threshold
        self._rolling_window = rolling_window
        self._rolling_decay = rolling_decay
        self._min_participation = min_participation_for_drift
        self._activity_divergence_threshold = activity_divergence_threshold
        self._activity_provider = activity_provider

        # agent_wallet -> _AgentState
        self._agents: dict[str, _AgentState] = {}

    # -- Public API ----------------------------------------------------------

    def observe(
        self,
        agent_wallet: str,
        epoch: int,
        aggregated_score: int,
        per_node_scores: Mapping[str, int],
        cluster_median: int,
    ) -> DriftFlag:
        """
        Record one agent's aggregated outcome for one epoch and produce the
        drift flag for THIS epoch.

        `per_node_scores` is the post-exclusion honest set: the nodes whose
        scores survived the per-epoch deviation gate. Signed deviations are
        tracked for every contributing node so the rolling-window node
        attribution can identify slow-drift attackers whose individual
        epoch deviations never crossed the 30% gate.
        """
        state = self._agents.setdefault(agent_wallet, _AgentState())

        # ── Velocity: epoch-over-epoch change ──────────────────────────────
        previous_score = state.history[-1][1] if state.history else 0
        velocity = self._signed_fraction(aggregated_score, previous_score)

        # ── Baseline: exponentially-decayed mean over the window ───────────
        baseline = self._rolling_baseline(state)
        baseline_deviation = self._signed_fraction(aggregated_score, int(round(baseline)))

        reasons: list[str] = []
        if state.history and abs(velocity) > self._velocity_threshold:
            reasons.append(DRIFT_REASON_VELOCITY)
        if baseline > 0 and abs(baseline_deviation) > self._baseline_threshold:
            reasons.append(DRIFT_REASON_BASELINE)

        # ── Activity cross-check (optional) ────────────────────────────────
        activity_divergence = 0.0
        if self._activity_provider is not None and state.history:
            activity_divergence = self._activity_divergence(
                agent_wallet, velocity
            )
            if abs(activity_divergence) > self._activity_divergence_threshold:
                reasons.append(DRIFT_REASON_ACTIVITY)

        # ── Update rolling state AFTER computing this epoch's flag ─────────
        state.history.append((epoch, aggregated_score))
        while len(state.history) > self._rolling_window:
            state.history.popleft()

        for node_id, score in per_node_scores.items():
            dev = self._signed_fraction(score, cluster_median)
            history = state.node_signed_devs.setdefault(node_id, deque())
            history.append((epoch, dev))
            while len(history) > self._rolling_window:
                history.popleft()

        if reasons:
            logger.warning(
                "drift flag: agent=%s epoch=%d score=%d prev=%d baseline=%.1f "
                "velocity=%.3f baseline_dev=%.3f reasons=%s",
                agent_wallet, epoch, aggregated_score, previous_score,
                baseline, velocity, baseline_deviation, ",".join(reasons),
            )

        return DriftFlag(
            agent_wallet=agent_wallet,
            epoch=epoch,
            aggregated_score=aggregated_score,
            reasons=tuple(reasons),
            previous_score=previous_score,
            baseline=baseline,
            velocity=velocity,
            baseline_deviation=baseline_deviation,
            activity_divergence=activity_divergence,
        )

    def node_attributions(self, agent_wallet: str) -> tuple[NodeDriftAttribution, ...]:
        """
        The per-node slow-drift attribution for one agent, computed over
        the current rolling window. Nodes are sorted by node_id for
        deterministic ordering.
        """
        state = self._agents.get(agent_wallet)
        if state is None:
            return ()

        attributions: list[NodeDriftAttribution] = []
        for node_id in sorted(state.node_signed_devs):
            history = state.node_signed_devs[node_id]
            if not history:
                continue
            signed_devs = [d for _, d in history]
            mean_signed = sum(signed_devs) / len(signed_devs)
            is_drift = (
                len(signed_devs) >= self._min_participation
                and abs(mean_signed) > self._node_drift_threshold
            )
            attributions.append(NodeDriftAttribution(
                node_id=node_id,
                epochs_contributed=len(signed_devs),
                mean_signed_deviation=mean_signed,
                is_drift_attacker=is_drift,
            ))
        return tuple(attributions)

    def drift_attackers(self, agent_wallet: str) -> tuple[str, ...]:
        """Node ids currently classified as slow-drift attackers for an agent."""
        return tuple(
            a.node_id for a in self.node_attributions(agent_wallet)
            if a.is_drift_attacker
        )

    def history_for(self, agent_wallet: str) -> tuple[tuple[int, int], ...]:
        """The current rolling (epoch, score) history for one agent."""
        state = self._agents.get(agent_wallet)
        if state is None:
            return ()
        return tuple(state.history)

    # -- Internals -----------------------------------------------------------

    @staticmethod
    def _signed_fraction(value: int, reference: int) -> float:
        """
        (value - reference) / reference, signed. When reference is 0 we
        divide by 1 to avoid blow-up; the resulting "fraction" then equals
        the raw delta, which crosses any sane threshold for non-zero values
        and correctly registers the bootstrap-from-zero case as significant.
        """
        denom = reference if reference > 0 else 1
        return (value - reference) / denom

    def _rolling_baseline(self, state: _AgentState) -> float:
        """
        Exponentially-decayed mean of the agent's score history. The most
        recent observation gets weight 1; each older observation is
        multiplied by `rolling_decay` per step back. Returns 0.0 if the
        history is empty (i.e. first epoch — no baseline yet).
        """
        if not state.history:
            return 0.0
        # Walk newest -> oldest applying decay.
        ordered = list(state.history)
        weight = 1.0
        weighted_sum = 0.0
        total_weight = 0.0
        for _epoch, score in reversed(ordered):
            weighted_sum += weight * score
            total_weight += weight
            weight *= self._rolling_decay
        return weighted_sum / total_weight if total_weight > 0 else 0.0

    def _activity_divergence(
        self, agent_wallet: str, score_velocity: float,
    ) -> float:
        """
        How far the score's epoch-over-epoch movement diverges from the
        agent's on-chain activity movement. Positive means the score grew
        faster than activity; negative means activity grew faster (or
        score fell while activity rose).

        Returns 0.0 if the provider has insufficient history.
        """
        provider = self._activity_provider
        if provider is None:
            return 0.0
        try:
            recent = provider.history(agent_wallet, 2)
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "activity provider failed for %s: %s", agent_wallet, exc,
            )
            return 0.0
        if len(recent) < 2:
            return 0.0
        prev, curr = recent[-2], recent[-1]
        prev_metric = (
            prev.volume_metric if prev.volume_metric > 0 else float(prev.tx_count)
        )
        curr_metric = (
            curr.volume_metric if curr.volume_metric > 0 else float(curr.tx_count)
        )
        if prev_metric <= 0:
            return 0.0
        activity_velocity = (curr_metric - prev_metric) / prev_metric
        return score_velocity - activity_velocity


# =============================================================================
# Convenience factory — wires the default thresholds + an optional provider
# =============================================================================


def default_drift_detector(
    activity_provider: ActivityProvider | None = None,
) -> DriftDetector:
    """The detector wired with the documented production thresholds."""
    return DriftDetector(activity_provider=activity_provider)


# Type used by callers that want to inject a custom drift-emitter alongside
# (or in place of) the default DriftDetector. Mirrors the ChallengeFn shape
# in byzantine_watchdog.py.
DriftEmitter = Callable[[DriftFlag], None]
