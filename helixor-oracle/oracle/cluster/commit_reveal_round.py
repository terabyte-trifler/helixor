"""
oracle/cluster/commit_reveal_round.py — one commit-reveal round.

A `CommitRevealRound` is the state machine for ONE epoch's commit-reveal
protocol, from one node's point of view. It tracks:

  - which peers have COMMITTED (Phase 1) and what hash,
  - which peers have REVEALED (Phase 2) and whether the reveal VERIFIED,
  - the phase DEADLINES, so a node that misses a phase is timed out.

PHASES
------
    OPEN_COMMIT  -> collecting commits. Closes when every node has
                    committed, OR the commit deadline passes.
    OPEN_REVEAL  -> collecting reveals. A reveal is accepted only if it
                    verifies against that node's commit. Closes when every
                    committed node has revealed, OR the reveal deadline
                    passes.
    CLOSED       -> the round is done. The verified reveals are the score
                    set the cluster aggregates (Day-24 median).

TIMEOUT = FAULT
---------------
A node that does not commit before the commit deadline, or commits but
does not reveal a VALID score before the reveal deadline, is FAULTY for
this round — it simply does not contribute. This is the same treatment an
offline node got in Day 24; commit-reveal just adds "committed but failed
to reveal" as another way to be faulty. As long as a quorum of nodes
reveal validly, the round still produces a score.

A node may NOT:
  - commit twice (the first commit binds),
  - reveal before the commit phase closes (no peeking head start),
  - reveal a (scores, nonce) that does not hash to its commit (a copier).

DETERMINISM
-----------
The round logic is pure given its inputs and an explicit clock value —
time is passed IN (`now`), never read from the system clock here — so the
state machine is fully testable and reproducible.
"""

from __future__ import annotations

import enum
from collections.abc import Sequence
from dataclasses import dataclass, field

from oracle.cluster.commit_reveal import verify_reveal
from oracle.cluster.messages import AgentScore


# =============================================================================
# Phase
# =============================================================================

class RoundPhase(enum.Enum):
    """The phase of a commit-reveal round."""
    OPEN_COMMIT = "open_commit"
    OPEN_REVEAL = "open_reveal"
    CLOSED      = "closed"


# =============================================================================
# Per-node records
# =============================================================================

@dataclass(frozen=True, slots=True)
class CommitRecord:
    """A node's Phase-1 commit."""
    node_id:     str
    commit_hash: bytes
    committed_at: float        # the `now` value when it was accepted


@dataclass(frozen=True, slots=True)
class RevealRecord:
    """A node's Phase-2 reveal — and whether it verified."""
    node_id:    str
    scores:     tuple[AgentScore, ...]
    verified:   bool
    revealed_at: float
    reason:     str = ""


# =============================================================================
# Outcomes
# =============================================================================

class CommitRejected(Exception):
    """A commit was not accepted (wrong phase, duplicate, unknown node)."""


class RevealRejected(Exception):
    """A reveal was not accepted (wrong phase, no commit, hash mismatch)."""


# =============================================================================
# The round
# =============================================================================

class CommitRevealRound:
    """
    One epoch's commit-reveal round.

    Construct with the set of expected node ids and the two phase
    deadlines. Feed it commits, then reveals, advancing `now` as the
    operator's clock moves. Query `verified_scores()` once CLOSED.
    """

    def __init__(
        self,
        epoch:           int,
        node_ids:        Sequence[str],
        *,
        commit_deadline: float,
        reveal_deadline: float,
        opened_at:       float = 0.0,
    ) -> None:
        if not node_ids:
            raise ValueError("a round needs at least one node")
        if len(set(node_ids)) != len(node_ids):
            raise ValueError("duplicate node id in round membership")
        if not (opened_at <= commit_deadline <= reveal_deadline):
            raise ValueError(
                "deadlines must satisfy opened_at <= commit <= reveal"
            )
        self._epoch = epoch
        self._node_ids = set(node_ids)
        self._commit_deadline = commit_deadline
        self._reveal_deadline = reveal_deadline
        self._opened_at = opened_at

        self._commits: dict[str, CommitRecord] = {}
        self._reveals: dict[str, RevealRecord] = {}
        self._phase = RoundPhase.OPEN_COMMIT

    # ── Phase ───────────────────────────────────────────────────────────────

    @property
    def epoch(self) -> int:
        return self._epoch

    def phase(self, now: float) -> RoundPhase:
        """
        The round's phase at time `now`. Phases advance on either condition:
        everyone has acted, or the deadline has passed.
        """
        self._advance(now)
        return self._phase

    def _advance(self, now: float) -> None:
        """Advance the phase if its closing condition is met."""
        if self._phase is RoundPhase.OPEN_COMMIT:
            everyone_committed = len(self._commits) == len(self._node_ids)
            if everyone_committed or now >= self._commit_deadline:
                self._phase = RoundPhase.OPEN_REVEAL
        if self._phase is RoundPhase.OPEN_REVEAL:
            # Every node that COMMITTED has either revealed or is moot;
            # the round closes when all committers revealed, or time is up.
            committers = set(self._commits)
            all_revealed = committers.issubset(set(self._reveals))
            if (committers and all_revealed) or now >= self._reveal_deadline:
                self._phase = RoundPhase.CLOSED

    # ── Phase 1: commit ─────────────────────────────────────────────────────

    def submit_commit(
        self, node_id: str, commit_hash: bytes, *, now: float,
    ) -> CommitRecord:
        """
        Record a node's Phase-1 commit. Raises `CommitRejected` if the node
        is unknown, the commit phase has closed, or the node already
        committed (the first commit binds — it cannot be replaced).
        """
        self._advance(now)
        if node_id not in self._node_ids:
            raise CommitRejected(f"{node_id} is not a member of this round")
        if self._phase is not RoundPhase.OPEN_COMMIT:
            raise CommitRejected(
                f"commit phase is closed (phase={self._phase.value}) — "
                f"{node_id} committed too late"
            )
        if node_id in self._commits:
            raise CommitRejected(
                f"{node_id} already committed — a commit cannot be replaced"
            )
        if len(commit_hash) != 32:
            raise CommitRejected("commit_hash must be a 32-byte sha256 digest")

        record = CommitRecord(
            node_id=node_id, commit_hash=commit_hash, committed_at=now,
        )
        self._commits[node_id] = record
        self._advance(now)
        return record

    # ── Phase 2: reveal ─────────────────────────────────────────────────────

    def submit_reveal(
        self,
        node_id: str,
        scores:  Sequence[AgentScore],
        nonce:   bytes,
        *,
        now:     float,
    ) -> RevealRecord:
        """
        Record a node's Phase-2 reveal.

        The reveal is VERIFIED against the node's Phase-1 commit: the
        recomputed sha256(canonical(scores) || nonce) must equal the
        committed hash. A reveal is REJECTED outright (raises
        `RevealRejected`) if:
          - the reveal phase is not open (too early — no peeking — or the
            round has closed),
          - the node never committed (you cannot reveal without a commit).

        A reveal that arrives in-phase from a committed node but whose hash
        does NOT match is RECORDED with `verified=False` — it is kept for
        the audit trail (this is how a copier is caught) but does not count.
        """
        self._advance(now)
        if self._phase is RoundPhase.OPEN_COMMIT:
            raise RevealRejected(
                f"{node_id} tried to reveal during the commit phase — "
                f"reveals are not accepted until all commits are in"
            )
        if self._phase is RoundPhase.CLOSED:
            raise RevealRejected(
                f"the round has closed — {node_id} revealed too late"
            )
        commit = self._commits.get(node_id)
        if commit is None:
            raise RevealRejected(
                f"{node_id} has no commit — cannot reveal without committing"
            )
        if node_id in self._reveals:
            raise RevealRejected(f"{node_id} already revealed")

        # Verify the reveal against the commit.
        ok = verify_reveal(commit.commit_hash, scores, nonce)
        record = RevealRecord(
            node_id=node_id,
            scores=tuple(scores),
            verified=ok,
            revealed_at=now,
            reason="" if ok else (
                "hash mismatch — revealed scores do not match the commit "
                "(node did not compute these scores independently)"
            ),
        )
        self._reveals[node_id] = record
        self._advance(now)
        return record

    # ── Results ─────────────────────────────────────────────────────────────

    def committed_nodes(self) -> frozenset[str]:
        return frozenset(self._commits)

    def revealed_nodes(self) -> frozenset[str]:
        return frozenset(self._reveals)

    def verified_nodes(self) -> frozenset[str]:
        """Nodes whose reveal verified against their commit."""
        return frozenset(
            nid for nid, r in self._reveals.items() if r.verified
        )

    def faulty_nodes(self, now: float) -> frozenset[str]:
        """
        Nodes that are FAULTY for this round at time `now`: a node is
        faulty if it did not commit, committed but did not reveal, or
        revealed something that failed verification. Meaningful once the
        round is CLOSED.
        """
        self._advance(now)
        faulty = set()
        for nid in self._node_ids:
            reveal = self._reveals.get(nid)
            if reveal is None or not reveal.verified:
                faulty.add(nid)
        return frozenset(faulty)

    def verified_scores(self, now: float) -> dict[str, tuple[AgentScore, ...]]:
        """
        The verified score sets — node_id -> scores — for every node whose
        reveal verified. This is what the cluster aggregates (Day-24
        median). Only meaningful once the round is CLOSED; calling it
        earlier returns whatever has verified so far.
        """
        self._advance(now)
        return {
            nid: r.scores
            for nid, r in self._reveals.items()
            if r.verified
        }

    def reveal_record(self, node_id: str) -> RevealRecord | None:
        """The reveal record for a node — for inspecting why one failed."""
        return self._reveals.get(node_id)
