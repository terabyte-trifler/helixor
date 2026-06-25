"""
api/byzantine_repo.py — read repository for Byzantine flags + challenges.

The runbooks call these endpoints when an alert fires:
  * /byzantine/recent       — what was flagged in the last hour
  * /byzantine/strikes      — current strike counts per node
  * /byzantine/per_node     — what each node revealed for one (epoch, agent)
  * /challenges?node=X      — the on-chain challenges against a node

Production reads these from the indexer's mirror of the on-chain
`OracleChallenge` PDAs and a `byzantine_flags` event-history table the
indexer populates from the cluster's logs. Tests use the in-memory repo.

WHY THESE LIVE ON THE READ-SIDE
-------------------------------
Day 26 produces these events; they are LOGGED by the cluster and
PERSISTED on-chain. The cluster runtime does not need to read them back
— the watchdog is purely write-side. The API and the runbooks are the
read consumers, so the read repo lives here in phylanx-api, not in
phylanx-oracle.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol


# =============================================================================
# Per-epoch Byzantine flag record
# =============================================================================

@dataclass(frozen=True, slots=True)
class ByzantineFlagRecord:
    """One Byzantine flag fired during one epoch — what the watchdog saw."""
    node_id:        str
    epoch:          int
    subject_agent:  str
    accused_score:  int
    cluster_median: int
    deviation:      float

    def __post_init__(self) -> None:
        if self.deviation < 0:
            raise ValueError("deviation cannot be negative")


# =============================================================================
# Per-node strike record (the watchdog's view)
# =============================================================================

@dataclass(frozen=True, slots=True)
class StrikeSummary:
    node_id:        str
    strikes:        int
    flagged_epochs: tuple[int, ...]
    challenged:     bool


# =============================================================================
# Per-(epoch, agent, node) reveal — what each node SAID for this agent
# =============================================================================

@dataclass(frozen=True, slots=True)
class NodeRevealRecord:
    """Used by the runbook query: 'what did each node report for $AGENT?'"""
    node_id:      str
    epoch:        int
    agent_wallet: str
    score:        int


# =============================================================================
# On-chain challenge record (mirror of the OracleChallenge PDA — Day 21)
# =============================================================================

@dataclass(frozen=True, slots=True)
class ChallengeRecord:
    challenge_index: int            # the per-oracle counter index
    accused_node:    str
    proof_type:      int            # 0 = ConflictingScores (Day 21)
    subject_epoch:   int
    subject_agent:   str
    accused_score:   int
    cluster_median:  int
    evidence_hash:   str            # hex
    status:          str            # "pending" | "upheld" | "dismissed"
    filed_at:        int            # unix timestamp


# =============================================================================
# The protocol
# =============================================================================

class ByzantineRepository(Protocol):

    def recent_flags(
        self, *, since_epoch: int | None = None, limit: int = 100,
    ) -> list[ByzantineFlagRecord]: ...

    def strike_summary(self) -> list[StrikeSummary]: ...

    def per_node_reveals(
        self, *, epoch: int, agent_wallet: str,
    ) -> list[NodeRevealRecord]: ...

    def challenges_for(self, node_id: str) -> list[ChallengeRecord]: ...


# =============================================================================
# In-memory implementation
# =============================================================================

class InMemoryByzantineRepo:
    """A deterministic in-memory implementation for tests."""

    def __init__(
        self,
        flags:    Iterable[ByzantineFlagRecord] | None = None,
        strikes:  Iterable[StrikeSummary] | None = None,
        reveals:  Iterable[NodeRevealRecord] | None = None,
        challenges: Iterable[ChallengeRecord] | None = None,
    ) -> None:
        self._flags:   list[ByzantineFlagRecord] = list(flags or ())
        self._strikes: dict[str, StrikeSummary]  = {
            s.node_id: s for s in (strikes or ())
        }
        self._reveals: list[NodeRevealRecord]    = list(reveals or ())
        self._challenges: list[ChallengeRecord]  = list(challenges or ())

    # ── Writes (test helpers) ───────────────────────────────────────────────

    def add_flag(self, flag: ByzantineFlagRecord) -> None:
        self._flags.append(flag)

    def set_strikes(self, summary: StrikeSummary) -> None:
        self._strikes[summary.node_id] = summary

    def add_reveal(self, reveal: NodeRevealRecord) -> None:
        self._reveals.append(reveal)

    def add_challenge(self, challenge: ChallengeRecord) -> None:
        self._challenges.append(challenge)

    # ── Reads (the API path) ────────────────────────────────────────────────

    def recent_flags(
        self, *, since_epoch: int | None = None, limit: int = 100,
    ) -> list[ByzantineFlagRecord]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit out of bounds")
        out = [
            f for f in self._flags
            if since_epoch is None or f.epoch >= since_epoch
        ]
        out.sort(key=lambda f: (f.epoch, f.node_id), reverse=True)
        return out[:limit]

    def strike_summary(self) -> list[StrikeSummary]:
        return [self._strikes[k] for k in sorted(self._strikes)]

    def per_node_reveals(
        self, *, epoch: int, agent_wallet: str,
    ) -> list[NodeRevealRecord]:
        out = [
            r for r in self._reveals
            if r.epoch == epoch and r.agent_wallet == agent_wallet
        ]
        out.sort(key=lambda r: r.node_id)
        return out

    def challenges_for(self, node_id: str) -> list[ChallengeRecord]:
        out = [c for c in self._challenges if c.accused_node == node_id]
        out.sort(key=lambda c: c.challenge_index, reverse=True)
        return out
