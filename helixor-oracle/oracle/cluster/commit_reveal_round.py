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
                    committed node has revealed, when a partial-reveal
                    QUORUM of VERIFIED reveals has arrived (VULN-05), OR
                    the reveal deadline passes.
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

VULN-05 — partial reveals + reveal timeout
------------------------------------------
A node that commits but never reveals previously forced the cluster to
wait the FULL reveal window before producing a result. A single bribed or
network-disrupted node could therefore induce a per-epoch latency burn
on the whole cluster — the "reveal phase has no timeout" livelock.

Two guarantees are now pinned in this module:

  1. **Partial-reveal early close.** If the round was opened with a
     `min_reveals` quorum (typically `floor(n/2)+1`), the OPEN_REVEAL
     phase closes as soon as that many VERIFIED reveals are in — the
     cluster no longer waits on stragglers once it can produce a result.
     Late VERIFIED reveals that arrive after early-close but before the
     reveal deadline are still ACCEPTED for the audit trail and to keep
     the late-but-honest node out of the non-revealers set; the cluster
     just doesn't block on them.

  2. **Reveal timeout is hard.** Once `now >= reveal_deadline`, no
     reveal is accepted, regardless of phase. The non-revealers
     (committed but never produced a verified reveal) are surfaced via
     `non_revealers(now)` so the upstream watchdog can attribute slash
     strikes (`PROOF_NON_REVEAL`) per epoch they refused to reveal.

A node may NOT:
  - commit twice (the first commit binds),
  - reveal before the commit phase closes (no peeking head start),
  - reveal a (scores, nonce) that does not hash to its commit (a copier),
  - reveal once the reveal-deadline timeout has elapsed.

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

from oracle.cluster.commit_reveal import AlgoVersion, verify_reveal
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


class VersionMismatch(CommitRejected):
    """
    VULN-22: a commit was rejected because its (scoring_algo_version,
    scoring_weights_version) does not match the round's pinned version.
    The runner treats this distinctly from a generic `CommitRejected`:
    the node is SILENTLY EXCLUDED from this round (no commit recorded,
    no Byzantine flag, no slash) until it upgrades to the cluster
    version. A node that shows up at this same step every epoch is in
    the upgrade-delay window, not malicious.
    """


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
        # VULN-05: when set, the OPEN_REVEAL phase closes as soon as this
        # many VERIFIED reveals are in — the partial-reveal quorum that
        # kills the "one node holds the cluster hostage" livelock. Leave
        # unset (None) to preserve the legacy "wait for all committers or
        # the deadline" behaviour the pure round-state tests pin.
        min_reveals:     int | None = None,
        # VULN-15: the agent-set snapshot hash this round is bound to. When
        # set, every commit hash AND every reveal verification folds this
        # in — so a verifier holding a different snapshot rejects reveals
        # that were computed against the committer's snapshot, surfacing
        # mid-epoch agent-set drift as a verification failure. None keeps
        # the pre-VULN-15 wire format for back-compat (existing pure round
        # tests do not pass a snapshot).
        snapshot_hash:   bytes | None = None,
        # VULN-22: pre-pin this round to a specific (scoring_algo_version,
        # scoring_weights_version). When set, every commit MUST carry this
        # version or it is rejected with `VersionMismatch` (silent exclude,
        # NOT Byzantine). When None, the round AUTO-PINS to the first
        # commit that carries a version — preserving the "honest cluster
        # all agrees on one version, mismatched stragglers silently sit
        # out" property without the runner having to pre-coordinate.
        # Both `None` (round + every commit lacking versions) keeps the
        # pre-VULN-22 wire format for back-compat with the legacy round
        # tests.
        pinned_algo_version: AlgoVersion | None = None,
    ) -> None:
        if not node_ids:
            raise ValueError("a round needs at least one node")
        if len(set(node_ids)) != len(node_ids):
            raise ValueError("duplicate node id in round membership")
        if not (opened_at <= commit_deadline <= reveal_deadline):
            raise ValueError(
                "deadlines must satisfy opened_at <= commit <= reveal"
            )
        if min_reveals is not None:
            if min_reveals < 1:
                raise ValueError("min_reveals must be >= 1")
            if min_reveals > len(node_ids):
                raise ValueError(
                    f"min_reveals={min_reveals} exceeds cluster size "
                    f"{len(node_ids)}"
                )
        if snapshot_hash is not None and len(snapshot_hash) != 32:
            raise ValueError(
                f"snapshot_hash must be a 32-byte sha256 digest, "
                f"got {len(snapshot_hash)}"
            )
        if pinned_algo_version is not None:
            algo_v, weights_v = pinned_algo_version
            if not (0 <= algo_v <= 0xFFFFFFFF):
                raise ValueError(
                    f"pinned scoring_algo_version out of u32 range: {algo_v}"
                )
            if not (0 <= weights_v <= 0xFFFFFFFF):
                raise ValueError(
                    f"pinned scoring_weights_version out of u32 range: "
                    f"{weights_v}"
                )
        self._epoch = epoch
        self._node_ids = set(node_ids)
        self._commit_deadline = commit_deadline
        self._reveal_deadline = reveal_deadline
        self._opened_at = opened_at
        self._min_reveals = min_reveals
        self._snapshot_hash = snapshot_hash
        # VULN-22: the pinned (algo, weights) version. When pre-set, every
        # commit must match. When None, auto-pinned to the FIRST commit
        # that carries a version — subsequent mismatched commits are
        # silently excluded via `VersionMismatch`.
        self._pinned_algo_version: AlgoVersion | None = pinned_algo_version

        self._commits: dict[str, CommitRecord] = {}
        self._reveals: dict[str, RevealRecord] = {}
        # VULN-22: nodes whose commit was rejected for a version mismatch.
        # Kept distinct from `_commits` (which only holds ACCEPTED commits)
        # so the runner can surface "excluded due to version drift" as a
        # NON-Byzantine state in its epoch report. A node may be retried
        # in a later epoch once it has upgraded — there is no "blacklist".
        self._version_mismatched: set[str] = set()
        self._phase = RoundPhase.OPEN_COMMIT
        # VULN-05: True once the round closed via the partial-reveal quorum
        # gate (as opposed to all-revealed or the timeout). Surfaced for
        # observability — the runner reports an early-close to operators.
        self._closed_by_quorum = False

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
            # the round closes when all committers revealed, when the
            # partial-reveal quorum (VULN-05) of VERIFIED reveals has
            # arrived, or time is up.
            committers = set(self._commits)
            all_revealed = committers.issubset(set(self._reveals))
            verified_count = sum(1 for r in self._reveals.values() if r.verified)
            quorum_close = (
                self._min_reveals is not None
                and verified_count >= self._min_reveals
            )
            if (
                (committers and all_revealed)
                or quorum_close
                or now >= self._reveal_deadline
            ):
                if quorum_close and not (committers and all_revealed):
                    # The cluster proceeded on partial reveals — record
                    # the reason so the runner can report it.
                    self._closed_by_quorum = True
                self._phase = RoundPhase.CLOSED

    # ── Phase 1: commit ─────────────────────────────────────────────────────

    def submit_commit(
        self,
        node_id:      str,
        commit_hash:  bytes,
        *,
        now:          float,
        algo_version: AlgoVersion | None = None,
    ) -> CommitRecord:
        """
        Record a node's Phase-1 commit. Raises `CommitRejected` if the node
        is unknown, the commit phase has closed, or the node already
        committed (the first commit binds — it cannot be replaced).

        VULN-22 — version pinning:
          * If the round was opened with a `pinned_algo_version`, any
            commit with `algo_version != pinned` is rejected with
            `VersionMismatch` (subclass of `CommitRejected`). The
            offending node is added to `version_mismatched_nodes()` and
            NOT recorded as a committer — the runner reads that set to
            surface "silently excluded due to version drift" in its
            report (NOT a Byzantine flag, NOT a slash).
          * If the round was opened with no pin and the FIRST commit
            carries an `algo_version`, the round auto-pins to it for the
            rest of the round.
          * If the round was opened with a pin and the commit omits
            `algo_version`, it is treated as a mismatch — a version-
            unaware commit cannot satisfy a pinned round.
          * If no commits ever carry a version, the round stays unpinned
            and the legacy pre-VULN-22 path runs unchanged (back-compat
            for the pure round-state tests).
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

        # VULN-22: pin / validate version BEFORE recording the commit so a
        # mismatched commit never lands in `_commits` (and so cannot later
        # be revealed against, even if the node tried).
        if self._pinned_algo_version is not None:
            if algo_version != self._pinned_algo_version:
                self._version_mismatched.add(node_id)
                raise VersionMismatch(
                    f"{node_id} commit carries algo_version="
                    f"{algo_version!r}, round is pinned to "
                    f"{self._pinned_algo_version!r} — silently excluded "
                    f"(NOT a Byzantine flag) until the node upgrades"
                )
        elif algo_version is not None:
            # Auto-pin from the first version-aware commit.
            self._pinned_algo_version = algo_version

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
        # VULN-05: the reveal-deadline timeout is the hard gate. A reveal
        # that arrives at-or-after `reveal_deadline` is rejected as "too
        # late" regardless of phase. A reveal that arrives BEFORE the
        # deadline is accepted even if the round already closed early on
        # the partial-reveal quorum — late honest reveals are still
        # recorded so the late-but-honest node is not falsely struck as a
        # non-revealer, even though the cluster did not block on them.
        if now >= self._reveal_deadline:
            raise RevealRejected(
                f"the reveal window has closed — {node_id} revealed too late"
            )
        commit = self._commits.get(node_id)
        if commit is None:
            raise RevealRejected(
                f"{node_id} has no commit — cannot reveal without committing"
            )
        if node_id in self._reveals:
            raise RevealRejected(f"{node_id} already revealed")

        # Verify the reveal against the commit. The snapshot_hash (VULN-15)
        # AND the pinned algo_version (VULN-22) are folded in if the round
        # was opened / pinned with them — a verifier with a different
        # snapshot or version rejects the reveal, surfacing mid-epoch
        # drift here rather than as silent score divergence.
        ok = verify_reveal(
            commit.commit_hash, scores, nonce,
            snapshot_hash=self._snapshot_hash,
            algo_version=self._pinned_algo_version,
        )
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

    def non_revealers(self, now: float) -> frozenset[str]:
        """
        VULN-05: nodes that COMMITTED but have not yet produced a reveal
        record at time `now`. Distinct from `faulty_nodes`, which also
        captures missed commits and failed verifications — non-revealers
        are specifically the "committed and went silent" attack vector
        the audit asks the watchdog to penalise.

        Intended to be called once the reveal window has elapsed (`now`
        past `reveal_deadline`); calling earlier returns whichever
        committed nodes have not yet revealed at that moment, which may
        include nodes still within their valid reveal window.
        """
        self._advance(now)
        revealed = set(self._reveals)
        return frozenset(nid for nid in self._commits if nid not in revealed)

    @property
    def closed_by_quorum(self) -> bool:
        """
        VULN-05: True iff the round closed via the partial-reveal quorum
        gate rather than all-revealed or the timeout. Surfaced for
        operator observability — repeated quorum closes mean stragglers
        are routinely missing the reveal window.
        """
        return self._closed_by_quorum

    @property
    def reveal_deadline(self) -> float:
        return self._reveal_deadline

    @property
    def min_reveals(self) -> int | None:
        return self._min_reveals

    @property
    def snapshot_hash(self) -> bytes | None:
        """
        VULN-15: the agent-set snapshot hash this round is bound to (or
        None for a legacy round opened without one). Exposed for the
        watchdog so it can attribute reveal failures to set-drift vs
        score-divergence cleanly.
        """
        return self._snapshot_hash

    @property
    def pinned_algo_version(self) -> AlgoVersion | None:
        """
        VULN-22: the (scoring_algo_version, scoring_weights_version)
        currently pinned for this round, or None if no version-aware
        commit has been recorded yet. After the first version-aware
        commit (or construction with `pinned_algo_version=`), every
        subsequent commit must match.
        """
        return self._pinned_algo_version

    def version_mismatched_nodes(self) -> frozenset[str]:
        """
        VULN-22: node ids whose commit was REJECTED because their
        (scoring_algo_version, scoring_weights_version) did not match the
        round's pinned version. These nodes are NOT in `committed_nodes`,
        NOT in `verified_nodes`, and MUST NOT be flagged as Byzantine —
        the runner reports them as the version-skew set for operator
        attention (it usually means an in-progress upgrade has not yet
        rolled out to every node).
        """
        return frozenset(self._version_mismatched)

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
