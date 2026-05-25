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


# =============================================================================
# Strike record
# =============================================================================

@dataclass(slots=True)
class StrikeRecord:
    """A node's Byzantine-strike history."""
    node_id:          str
    strikes:          int = 0
    # The epochs in which this node was flagged Byzantine.
    flagged_epochs:   list[int] = field(default_factory=list)
    # True once a challenge has been filed — a node is challenged once.
    challenged:       bool = False

    @property
    def at_threshold(self) -> bool:
        return self.strikes >= STRIKE_THRESHOLD


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
    # ProofType.ConflictingScores wire code (0) — see Day-21 oracle_challenge.
    proof_type:     int
    strikes:        int
    flagged_epochs: tuple[int, ...]
    # The epoch + agent whose conflicting score is cited as the proof.
    subject_epoch:  int
    subject_agent:  str
    # The node's deviating score vs the cluster median — the conflict.
    accused_score:  int
    cluster_median: int


# A challenge function files a ByzantineChallenge on-chain (via the
# slash-authority `challenge_oracle` instruction) and returns a record.
# Injected — production wires the instruction, tests pass a stub.
ChallengeFn = Callable[[ByzantineChallenge], object]


# ProofType.ConflictingScores wire code, mirroring the on-chain enum.
PROOF_CONFLICTING_SCORES = 0


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
