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


# Day 37 — label deviation. A node whose `failure_mode_bitmask` lies far
# from the cluster consensus is flagged for ONE epoch when its Hamming
# distance from the consensus bitmask crosses this threshold. The
# threshold is on the deviating-bit COUNT, not a fraction: a flat
# tolerance prevents label-flap from striking a node that disagrees on a
# single noisy detector (which would happen during a rolling kernel
# upgrade or a transient feature blip). Three bits ~ 4.7% of u64; few
# enough to catch a node lying about a class of failure modes, generous
# enough to absorb one noisy detector mismatch.
LABEL_DEVIATION_HAMMING_THRESHOLD = 3

# Day 37 — label-strike threshold. Per-epoch label deviation accumulates
# on its own track. Three strikes routes to a `PROOF_LABEL_DEVIATION`
# challenge, mirroring the conflicting-scores escalation cadence.
LABEL_STRIKE_THRESHOLD = 3


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
    # Day 37 — per-epoch label-deviation strikes (Hamming distance
    # above LABEL_DEVIATION_HAMMING_THRESHOLD). Soft track, accumulates
    # to LABEL_STRIKE_THRESHOLD before challenging.
    label_strikes:         int = 0
    label_epochs:          list[int] = field(default_factory=list)
    label_challenged:      bool = False
    # Day 37 — hard payload-hash mismatch strikes. A revealed payload
    # hash that disagrees with the honest-majority consensus is treated
    # as a hard deviation: every such epoch counts as a strike, and the
    # FIRST one already files the challenge — there is no flap window
    # for "I happened to compute a different kernel JSON on a 50-50
    # split"; the kernel is deterministic by spec, divergence here is
    # a bug or an attack.
    payload_hash_mismatch_strikes:   int = 0
    payload_hash_mismatch_epochs:    list[int] = field(default_factory=list)
    payload_hash_mismatch_challenged: bool = False

    @property
    def at_threshold(self) -> bool:
        return self.strikes >= STRIKE_THRESHOLD

    @property
    def at_drift_threshold(self) -> bool:
        return self.drift_strikes >= DRIFT_STRIKE_THRESHOLD

    @property
    def at_non_reveal_threshold(self) -> bool:
        return self.non_reveal_strikes >= NON_REVEAL_STRIKE_THRESHOLD

    @property
    def at_label_threshold(self) -> bool:
        return self.label_strikes >= LABEL_STRIKE_THRESHOLD


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
# Day 37: label-deviation evidence — a node whose `failure_mode_bitmask`
# diverged from the cluster consensus (Hamming distance above
# LABEL_DEVIATION_HAMMING_THRESHOLD) over LABEL_STRIKE_THRESHOLD epochs.
PROOF_LABEL_DEVIATION = 3
# Day 37: payload-hash mismatch — a node whose `diagnosis_payload_hash`
# disagreed with the honest-majority consensus on bytes. Hard deviation,
# no flap window. The kernel is deterministic; any divergence here is a
# bug or an attack.
PROOF_PAYLOAD_HASH_MISMATCH = 4


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
class LabelDeviationFlag:
    """
    Day 37 — one node's label-deviation flag for one commit-reveal epoch.

    The evidence is the Hamming distance from this node's
    `failure_mode_bitmask` to the cluster's consensus bitmask for one
    agent. Distances above `LABEL_DEVIATION_HAMMING_THRESHOLD` count as
    a strike; the watchdog accumulates them on the per-node label track
    and escalates after `LABEL_STRIKE_THRESHOLD` epochs.
    """
    node_id:        str
    epoch:          int
    subject_agent:  str
    accused_bitmask:  int
    consensus_bitmask: int
    hamming_distance: int


@dataclass(frozen=True, slots=True)
class PayloadHashMismatchFlag:
    """
    Day 37 — one node's payload-hash mismatch for one commit-reveal epoch.

    The kernel is deterministic by spec; a node whose
    `diagnosis_payload_hash` disagrees with the honest-majority consensus
    has either a kernel bug or is lying about which bytes it computed.
    Either way it is excluded from the cert signing set IMMEDIATELY and
    the first occurrence files the challenge — no flap window.
    """
    node_id:           str
    epoch:             int
    subject_agent:     str
    accused_hash:      bytes
    consensus_hash:    bytes


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

    # ── Day 37 — label-deviation attribution (soft) ────────────────────────

    def record_label_deviations(
        self,
        epoch: int,
        flags: Iterable["LabelDeviationFlag"],
        *,
        challenge_fn: ChallengeFn | None = None,
    ) -> list[ByzantineChallenge]:
        """
        Record one epoch's label-deviation flags. Each named node gains
        ONE label strike (deduped per epoch even if the node deviated
        across several agents — the WORST deviation is cited). A node
        crossing `LABEL_STRIKE_THRESHOLD` is challenged once with
        ProofType.LabelDeviation.

        Mirrors `record_drift_attackers`: idempotent across re-runs of
        the same epoch (a node already struck for that epoch is not
        double-struck), and the first threshold-crossing files exactly
        one challenge through the injected `ChallengeFn`.
        """
        flags_by_node: dict[str, "LabelDeviationFlag"] = {}
        for flag in flags:
            if flag.epoch != epoch:
                raise ValueError(
                    f"label-deviation flag epoch {flag.epoch} != "
                    f"record_epoch {epoch}"
                )
            existing = flags_by_node.get(flag.node_id)
            if existing is None or flag.hamming_distance > existing.hamming_distance:
                flags_by_node[flag.node_id] = flag

        filed: list[ByzantineChallenge] = []
        for node_id, flag in sorted(flags_by_node.items()):
            record = self._strikes.setdefault(
                node_id, StrikeRecord(node_id=node_id),
            )
            if epoch in record.label_epochs:
                continue                              # already counted
            record.label_strikes += 1
            record.label_epochs.append(epoch)
            logger.warning(
                "label-deviation flag: node %s, epoch %d, label-strike "
                "%d/%d (hamming=%d, agent=%s)",
                node_id, epoch,
                record.label_strikes, LABEL_STRIKE_THRESHOLD,
                flag.hamming_distance, flag.subject_agent,
            )
            if (
                record.label_strikes >= LABEL_STRIKE_THRESHOLD
                and not record.label_challenged
            ):
                challenge = ByzantineChallenge(
                    accused_node=node_id,
                    proof_type=PROOF_LABEL_DEVIATION,
                    strikes=record.label_strikes,
                    flagged_epochs=tuple(record.label_epochs),
                    subject_epoch=flag.epoch,
                    subject_agent=flag.subject_agent,
                    accused_score=flag.accused_bitmask & 0xFFFFFFFF,
                    cluster_median=flag.consensus_bitmask & 0xFFFFFFFF,
                )
                record.label_challenged = True
                filed.append(challenge)
                logger.error(
                    "node %s reached %d label-strikes — filing "
                    "challenge_oracle (LabelDeviation)",
                    node_id, record.label_strikes,
                )
                if challenge_fn is not None:
                    challenge_fn(challenge)
        return filed

    def label_strikes_for(self, node_id: str) -> int:
        record = self._strikes.get(node_id)
        return record.label_strikes if record else 0

    def is_label_challenged(self, node_id: str) -> bool:
        record = self._strikes.get(node_id)
        return record.label_challenged if record else False

    # ── Day 37 — payload-hash mismatch (hard) ──────────────────────────────

    def record_payload_hash_mismatches(
        self,
        epoch: int,
        flags: Iterable["PayloadHashMismatchFlag"],
        *,
        challenge_fn: ChallengeFn | None = None,
    ) -> list[ByzantineChallenge]:
        """
        Record one epoch's payload-hash mismatches. The kernel is
        deterministic by spec, so a mismatch is treated as a HARD
        deviation: the strike is recorded AND the challenge is filed on
        the FIRST occurrence — no `LABEL_STRIKE_THRESHOLD`-style flap
        window.

        Dedup per node per epoch (multiple agents → ONE strike); a node
        already challenged for payload-hash mismatch is not double-charged.
        """
        flags_by_node: dict[str, "PayloadHashMismatchFlag"] = {}
        for flag in flags:
            if flag.epoch != epoch:
                raise ValueError(
                    f"payload-hash mismatch flag epoch {flag.epoch} != "
                    f"record_epoch {epoch}"
                )
            flags_by_node.setdefault(flag.node_id, flag)

        filed: list[ByzantineChallenge] = []
        for node_id, flag in sorted(flags_by_node.items()):
            record = self._strikes.setdefault(
                node_id, StrikeRecord(node_id=node_id),
            )
            if epoch in record.payload_hash_mismatch_epochs:
                continue
            record.payload_hash_mismatch_strikes += 1
            record.payload_hash_mismatch_epochs.append(epoch)
            logger.error(
                "payload-hash mismatch: node %s, epoch %d, agent=%s "
                "(accused=%s, consensus=%s)",
                node_id, epoch, flag.subject_agent,
                flag.accused_hash.hex()[:16] if flag.accused_hash else "<empty>",
                flag.consensus_hash.hex()[:16] if flag.consensus_hash else "<empty>",
            )
            if not record.payload_hash_mismatch_challenged:
                challenge = ByzantineChallenge(
                    accused_node=node_id,
                    proof_type=PROOF_PAYLOAD_HASH_MISMATCH,
                    strikes=record.payload_hash_mismatch_strikes,
                    flagged_epochs=tuple(record.payload_hash_mismatch_epochs),
                    subject_epoch=flag.epoch,
                    subject_agent=flag.subject_agent,
                    accused_score=0,
                    cluster_median=0,
                )
                record.payload_hash_mismatch_challenged = True
                filed.append(challenge)
                logger.error(
                    "node %s — filing challenge_oracle "
                    "(PayloadHashMismatch) on first occurrence",
                    node_id,
                )
                if challenge_fn is not None:
                    challenge_fn(challenge)
        return filed

    def payload_hash_mismatch_strikes_for(self, node_id: str) -> int:
        record = self._strikes.get(node_id)
        return record.payload_hash_mismatch_strikes if record else 0

    def is_payload_hash_mismatch_challenged(self, node_id: str) -> bool:
        record = self._strikes.get(node_id)
        return record.payload_hash_mismatch_challenged if record else False

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
