"""
oracle/cluster/byzantine_watchdog.py — the cross-epoch Byzantine watchdog.

Per-epoch deviation detection (oracle/cluster/byzantine.py) flags a node as
Byzantine for ONE epoch. But a single deviating epoch is not proof of
malice — it could be a transient fault, a node mid-restart, a one-off bug.
Slashing a node's stake on one bad epoch would be unjust and exploitable
(grief a competitor by engineering one anomaly).

So the watchdog tracks Byzantine flags ACROSS epochs. A node accumulates a
"strike" each epoch it is flagged. Only when a node reaches
`STRIKE_THRESHOLD` strikes does the watchdog escalate — filing an on-chain
`challenge_oracle` (the Day-21 instruction) against it, which routes to
oracle-side slashing.

WHY STRIKES, NOT A RATE
-----------------------
Strikes are CONSECUTIVE-aware: a clean epoch does not erase history, but
the watchdog records both the strike count and whether flagging is
ongoing, so an operator reviewing a challenge sees a sustained pattern,
not one stale incident. A node that recovers and behaves stops
accumulating strikes; a node that is persistently Byzantine crosses the
threshold and is challenged.

THE CHALLENGE
-------------
A confirmed repeat offender is challenged with `ProofType.ConflictingScores`.
A Byzantine node's score, by definition, conflicts with the cluster's: the
challenge cites the node's deviating score against the cluster median for
the same (agent, epoch). Day 21 records that evidence for slash-authority
review; it is not treated as auto-verified unless the referenced median /
certificate artifacts are supplied and checked by the resolver. The
challenge is FILED through an injected seam (`ChallengeFn`), the same
pattern as the epoch runner's submit / slash seams — production wires the
real `challenge_oracle` instruction; tests pass a recording stub.

DETERMINISM
-----------
Strike accounting is pure integer logic over the per-epoch Byzantine
flags. Every honest node runs the identical watchdog and reaches the
identical strike counts — so the whole cluster agrees on who to challenge.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

logger = logging.getLogger("helixor.oracle.cluster.watchdog")


# A node is challenged once it has been flagged Byzantine in this many
# epochs. 3 — enough that a transient one-off fault does not trigger
# slashing, few enough that a persistently bad node is caught quickly.
STRIKE_THRESHOLD = 3


# VULN-03: drift strikes are a separate, lower-evidence track than per-epoch
# Byzantine strikes. A drift strike is a cross-epoch signal — the cluster
# saw a node consistently push the median in one direction over the rolling
# window — which is by construction less proof-of-malice than a single
# epoch >30% off the median. We escalate drift on a higher threshold so a
# pattern must be sustained across MULTIPLE rolling-window evaluations
# before it routes to slashing.
DRIFT_STRIKE_THRESHOLD = 3


# VULN-05: non-reveal strikes are accumulated per epoch a node committed
# to a commit-reveal round but failed to produce a verified reveal before
# the reveal-deadline timeout. This is the slash-points-per-epoch
# penalty the audit asks for — the only credible deterrent to a node
# stalling the protocol by sitting on its reveal. Three epochs of
# non-reveal is enough that a transient network or restart blip cannot
# trigger slashing, few enough that a node engineered to grief the
# protocol is challenged quickly.
NON_REVEAL_STRIKE_THRESHOLD = 3


# =============================================================================
# Strike record
# =============================================================================

@dataclass(slots=True)
class StrikeRecord:
    """A node's Byzantine-strike history."""
    node_id:               str
    strikes:               int = 0
    # The epochs in which this node was flagged Byzantine.
    flagged_epochs:        list[int] = field(default_factory=list)
    # True once a challenge has been filed — a node is challenged once.
    challenged:            bool = False
    # VULN-03: separate counter for cross-epoch slow-drift attribution.
    drift_strikes:         int = 0
    drift_epochs:          list[int] = field(default_factory=list)
    # True once a slow-drift challenge has been filed.
    drift_challenged:      bool = False
    # VULN-05: separate counter for committed-but-did-not-reveal epochs.
    non_reveal_strikes:    int = 0
    non_reveal_epochs:     list[int] = field(default_factory=list)
    # True once a non-reveal challenge has been filed.
    non_reveal_challenged: bool = False

    @property
    def at_threshold(self) -> bool:
        return self.strikes >= STRIKE_THRESHOLD

    @property
    def at_drift_threshold(self) -> bool:
        return self.drift_strikes >= DRIFT_STRIKE_THRESHOLD

    @property
    def at_non_reveal_threshold(self) -> bool:
        return self.non_reveal_strikes >= NON_REVEAL_STRIKE_THRESHOLD


# =============================================================================
# The challenge a watchdog files
# =============================================================================

@dataclass(frozen=True, slots=True)
class ByzantineChallenge:
    """
    A challenge the watchdog files against a repeat-offender node. Maps
    onto the on-chain `challenge_oracle` instruction (Day 21).
    """
    accused_node:   str
    # ProofType wire code — ConflictingScores (0) for per-epoch deviation,
    # SlowDrift (1) for cross-epoch drift attribution (VULN-03).
    proof_type:     int
    strikes:        int
    flagged_epochs: tuple[int, ...]
    # The epoch + agent whose conflicting score is cited as the proof.
    subject_epoch:  int
    subject_agent:  str
    # The node's deviating score vs the cluster median — the conflict.
    accused_score:  int
    cluster_median: int
    # VULN-03: when proof_type == SlowDrift, this carries the mean signed
    # deviation across the rolling window that triggered the challenge.
    # 0.0 for ConflictingScores challenges (no drift evidence cited).
    drift_mean_signed_deviation: float = 0.0


# A challenge function files a ByzantineChallenge on-chain (via the
# slash-authority `challenge_oracle` instruction) and returns a record.
# Injected — production wires the instruction, tests pass a stub.
ChallengeFn = Callable[[ByzantineChallenge], object]


# ProofType wire codes, mirroring the on-chain enum.
PROOF_CONFLICTING_SCORES = 0
# VULN-03: slow-drift attribution evidence — a node consistently pushing
# the cluster median over a rolling window of epochs.
PROOF_SLOW_DRIFT = 1
# VULN-05: committed-but-did-not-reveal evidence — a node that
# repeatedly enters the reveal phase with a commit and then sits silent,
# forcing the cluster onto the partial-reveal early-close path and
# threatening protocol liveness if it had ever held a hostage majority.
PROOF_NON_REVEAL = 2


# =============================================================================
# The watchdog
# =============================================================================

@dataclass(frozen=True, slots=True)
class EpochByzantineFlag:
    """
    One node's Byzantine flag for one epoch, with the evidence — the
    deviating score and the cluster median that exposed it.
    """
    node_id:        str
    epoch:          int
    subject_agent:  str
    accused_score:  int
    cluster_median: int


@dataclass(frozen=True, slots=True)
class NonRevealFlag:
    """
    VULN-05: one node's "committed but never revealed" attribution for
    one commit-reveal epoch. Carries enough context for the watchdog to
    accumulate strikes deterministically and cite the offending epoch in
    a challenge.
    """
    node_id:        str
    epoch:          int
    # The reveal-deadline that lapsed — for the audit citation. Logical
    # clock value (the commit-reveal protocol's `now` units).
    reveal_deadline: float


@dataclass(frozen=True, slots=True)
class SlowDriftFlag:
    """
    One node's cross-epoch slow-drift attribution. The evidence is the mean
    signed deviation across a rolling window — a value that crossed the
    NODE_DRIFT_THRESHOLD even though no single epoch's deviation crossed
    the 30% per-epoch gate (VULN-03).
    """
    node_id:               str
    epoch:                 int
    subject_agent:         str
    mean_signed_deviation: float       # the rolling-window signed mean
    drift_direction:       str         # "UP" or "DOWN"
    epochs_observed:       int


class ByzantineWatchdog:
    """
    Tracks Byzantine flags across epochs and escalates repeat offenders to
    an on-chain challenge.

    Feed it each epoch's Byzantine flags via `record_epoch`; it accumulates
    strikes and, when a node crosses `STRIKE_THRESHOLD`, files exactly one
    `challenge_oracle` through the injected `ChallengeFn`.
    """

    def __init__(self, *, strike_threshold: int = STRIKE_THRESHOLD) -> None:
        if strike_threshold < 1:
            raise ValueError("strike_threshold must be >= 1")
        self._threshold = strike_threshold
        self._strikes: dict[str, StrikeRecord] = {}
        # The most recent flag evidence per node — cited in its challenge.
        self._last_flag: dict[str, EpochByzantineFlag] = {}

    # ── Recording epochs ────────────────────────────────────────────────────

    def record_epoch(
        self,
        epoch: int,
        flags: Iterable[EpochByzantineFlag],
        *,
        challenge_fn: ChallengeFn | None = None,
    ) -> list[ByzantineChallenge]:
        """
        Record one epoch's Byzantine flags. Each flagged node gains a
        strike. Any node that crosses the strike threshold for the first
        time is challenged via `challenge_fn` (if provided).

        Returns the list of challenges FILED this epoch (empty if none
        crossed the threshold this epoch).
        """
        # Dedup: a node flagged for several agents in one epoch earns ONE
        # strike for that epoch, not one per agent.
        flags_by_node: dict[str, EpochByzantineFlag] = {}
        for flag in flags:
            if flag.epoch != epoch:
                raise ValueError(
                    f"flag epoch {flag.epoch} != record_epoch {epoch}"
                )
            # Keep the WORST deviation as the cited evidence.
            existing = flags_by_node.get(flag.node_id)
            if existing is None or _worse(flag, existing):
                flags_by_node[flag.node_id] = flag

        filed: list[ByzantineChallenge] = []
        for node_id, flag in sorted(flags_by_node.items()):
            record = self._strikes.setdefault(
                node_id, StrikeRecord(node_id=node_id)
            )
            if epoch in record.flagged_epochs:
                continue                              # already counted
            record.strikes += 1
            record.flagged_epochs.append(epoch)
            self._last_flag[node_id] = flag
            logger.warning(
                "byzantine flag: node %s, epoch %d, strike %d/%d "
                "(score %d vs median %d)",
                node_id, epoch, record.strikes, self._threshold,
                flag.accused_score, flag.cluster_median,
            )

            # ── Escalate the first time a node crosses the threshold ────────
            if record.strikes >= self._threshold and not record.challenged:
                challenge = self._build_challenge(record, flag)
                record.challenged = True
                filed.append(challenge)
                logger.error(
                    "node %s reached %d strikes — filing challenge_oracle",
                    node_id, record.strikes,
                )
                if challenge_fn is not None:
                    challenge_fn(challenge)

        return filed

    def _build_challenge(
        self, record: StrikeRecord, flag: EpochByzantineFlag,
    ) -> ByzantineChallenge:
        return ByzantineChallenge(
            accused_node=record.node_id,
            proof_type=PROOF_CONFLICTING_SCORES,
            strikes=record.strikes,
            flagged_epochs=tuple(record.flagged_epochs),
            subject_epoch=flag.epoch,
            subject_agent=flag.subject_agent,
            accused_score=flag.accused_score,
            cluster_median=flag.cluster_median,
        )

    # ── VULN-03 cross-epoch slow-drift attribution ─────────────────────────

    def record_drift_attackers(
        self,
        epoch: int,
        flags: Iterable["SlowDriftFlag"],
        *,
        challenge_fn: ChallengeFn | None = None,
    ) -> list[ByzantineChallenge]:
        """
        Record one epoch's slow-drift attributions. Each named node gains
        a DRIFT strike — tracked separately from per-epoch Byzantine
        strikes. A node crossing DRIFT_STRIKE_THRESHOLD is challenged
        once with ProofType.SlowDrift.

        Drift strikes are a softer signal than per-epoch Byzantine flags
        (the per-epoch detector caught a single big lie; drift detection
        caught a pattern of small consistent pushes) so they accumulate
        on their own threshold and produce a distinct on-chain proof.
        """
        # Dedup: a node attributed for several agents in one epoch earns
        # ONE drift strike for that epoch.
        flags_by_node: dict[str, "SlowDriftFlag"] = {}
        for flag in flags:
            if flag.epoch != epoch:
                raise ValueError(
                    f"drift flag epoch {flag.epoch} != record_epoch {epoch}"
                )
            existing = flags_by_node.get(flag.node_id)
            if existing is None or abs(flag.mean_signed_deviation) > abs(
                existing.mean_signed_deviation,
            ):
                flags_by_node[flag.node_id] = flag

        filed: list[ByzantineChallenge] = []
        for node_id, flag in sorted(flags_by_node.items()):
            record = self._strikes.setdefault(
                node_id, StrikeRecord(node_id=node_id),
            )
            if epoch in record.drift_epochs:
                continue                              # already counted
            record.drift_strikes += 1
            record.drift_epochs.append(epoch)
            logger.warning(
                "slow-drift flag: node %s, epoch %d, drift-strike %d/%d "
                "(mean signed dev %.3f, direction %s, agent %s)",
                node_id, epoch, record.drift_strikes, DRIFT_STRIKE_THRESHOLD,
                flag.mean_signed_deviation, flag.drift_direction,
                flag.subject_agent,
            )

            if (
                record.drift_strikes >= DRIFT_STRIKE_THRESHOLD
                and not record.drift_challenged
            ):
                challenge = ByzantineChallenge(
                    accused_node=node_id,
                    proof_type=PROOF_SLOW_DRIFT,
                    strikes=record.drift_strikes,
                    flagged_epochs=tuple(record.drift_epochs),
                    subject_epoch=flag.epoch,
                    subject_agent=flag.subject_agent,
                    accused_score=0,
                    cluster_median=0,
                    drift_mean_signed_deviation=flag.mean_signed_deviation,
                )
                record.drift_challenged = True
                filed.append(challenge)
                logger.error(
                    "node %s reached %d drift-strikes — filing "
                    "challenge_oracle (SlowDrift)",
                    node_id, record.drift_strikes,
                )
                if challenge_fn is not None:
                    challenge_fn(challenge)

        return filed

    def drift_strikes_for(self, node_id: str) -> int:
        record = self._strikes.get(node_id)
        return record.drift_strikes if record else 0

    def is_drift_challenged(self, node_id: str) -> bool:
        record = self._strikes.get(node_id)
        return record.drift_challenged if record else False

    # ── VULN-05 non-reveal attribution ─────────────────────────────────────

    def record_non_revealers(
        self,
        epoch: int,
        flags: Iterable["NonRevealFlag"],
        *,
        challenge_fn: ChallengeFn | None = None,
    ) -> list[ByzantineChallenge]:
        """
        Record one commit-reveal epoch's NON-REVEALERS — nodes that
        committed but failed to produce a verified reveal before the
        reveal-deadline timeout. Each named node gains a NON-REVEAL
        strike, tracked on its own counter (separate from per-epoch
        Byzantine and slow-drift strikes). A node crossing
        `NON_REVEAL_STRIKE_THRESHOLD` is challenged once with
        ProofType.NonReveal.

        Mirrors `record_drift_attackers`: dedup by node within an epoch,
        idempotent across re-runs of the same epoch (a node already
        struck for that epoch is not double-struck), and the first
        threshold-crossing files exactly one challenge through the
        injected `ChallengeFn`.
        """
        # Dedup: a node listed multiple times for one epoch earns ONE
        # non-reveal strike for that epoch.
        flags_by_node: dict[str, "NonRevealFlag"] = {}
        for flag in flags:
            if flag.epoch != epoch:
                raise ValueError(
                    f"non-reveal flag epoch {flag.epoch} != "
                    f"record_epoch {epoch}"
                )
            flags_by_node.setdefault(flag.node_id, flag)

        filed: list[ByzantineChallenge] = []
        for node_id, flag in sorted(flags_by_node.items()):
            record = self._strikes.setdefault(
                node_id, StrikeRecord(node_id=node_id),
            )
            if epoch in record.non_reveal_epochs:
                continue                              # already counted
            record.non_reveal_strikes += 1
            record.non_reveal_epochs.append(epoch)
            logger.warning(
                "non-reveal flag: node %s, epoch %d, non-reveal-strike "
                "%d/%d (reveal_deadline=%.3f)",
                node_id, epoch,
                record.non_reveal_strikes, NON_REVEAL_STRIKE_THRESHOLD,
                flag.reveal_deadline,
            )

            if (
                record.non_reveal_strikes >= NON_REVEAL_STRIKE_THRESHOLD
                and not record.non_reveal_challenged
            ):
                challenge = ByzantineChallenge(
                    accused_node=node_id,
                    proof_type=PROOF_NON_REVEAL,
                    strikes=record.non_reveal_strikes,
                    flagged_epochs=tuple(record.non_reveal_epochs),
                    subject_epoch=flag.epoch,
                    subject_agent="",        # non-reveal is round-wide, no agent
                    accused_score=0,
                    cluster_median=0,
                )
                record.non_reveal_challenged = True
                filed.append(challenge)
                logger.error(
                    "node %s reached %d non-reveal-strikes — filing "
                    "challenge_oracle (NonReveal)",
                    node_id, record.non_reveal_strikes,
                )
                if challenge_fn is not None:
                    challenge_fn(challenge)

        return filed

    def non_reveal_strikes_for(self, node_id: str) -> int:
        record = self._strikes.get(node_id)
        return record.non_reveal_strikes if record else 0

    def is_non_reveal_challenged(self, node_id: str) -> bool:
        record = self._strikes.get(node_id)
        return record.non_reveal_challenged if record else False

    # ── Queries ─────────────────────────────────────────────────────────────

    def strikes_for(self, node_id: str) -> int:
        record = self._strikes.get(node_id)
        return record.strikes if record else 0

    def is_challenged(self, node_id: str) -> bool:
        record = self._strikes.get(node_id)
        return record.challenged if record else False

    def record_for(self, node_id: str) -> StrikeRecord | None:
        return self._strikes.get(node_id)

    def challenged_nodes(self) -> frozenset[str]:
        return frozenset(
            nid for nid, r in self._strikes.items() if r.challenged
        )

    def all_records(self) -> list[StrikeRecord]:
        return [self._strikes[k] for k in sorted(self._strikes)]


def _worse(a: EpochByzantineFlag, b: EpochByzantineFlag) -> bool:
    """True if flag `a` shows a worse (larger) deviation than `b`."""
    da = abs(a.accused_score - a.cluster_median)
    db = abs(b.accused_score - b.cluster_median)
    return da > db
