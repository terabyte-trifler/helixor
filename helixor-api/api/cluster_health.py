"""
api/cluster_health.py — cluster-liveness + recent-epoch read repo.

Powers `/health/cluster`, the endpoint the `node_down.md` runbook curls.
Aggregates two pieces of read state:

  1. Per-node liveness  — node_id -> last-seen unix timestamp
  2. Recent epoch summaries — what was submitted, what failed quorum

Production reads from the indexer's `oracle_node_heartbeat` table (the
indexer writes a heartbeat row whenever a node publishes a commit) and
the `epoch_submission_log` table (the cluster writes one row per epoch).
Tests use the in-memory implementation.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class NodeHeartbeat:
    node_id:        str
    last_seen_unix: int
    epoch:          int               # the most-recent epoch we saw them in


@dataclass(frozen=True, slots=True)
class EpochSummary:
    epoch:            int
    submitted_count:  int             # agents whose certs landed
    agent_count:      int             # agents the cluster attempted
    verified_nodes:   tuple[str, ...] # passed commit-reveal
    byzantine_nodes:  tuple[str, ...]
    unreachable_nodes:tuple[str, ...]
    elapsed_seconds:  float
    computed_at:      datetime

    @property
    def submitted_all(self) -> bool:
        return self.submitted_count == self.agent_count


# =============================================================================
# Protocol
# =============================================================================

class ClusterHealthRepository(Protocol):

    def heartbeats(self) -> list[NodeHeartbeat]: ...

    def recent_epochs(self, *, limit: int = 10) -> list[EpochSummary]: ...


# =============================================================================
# In-memory implementation
# =============================================================================

class InMemoryClusterHealthRepo:

    def __init__(
        self,
        heartbeats:    Iterable[NodeHeartbeat] | None = None,
        epoch_summaries: Iterable[EpochSummary] | None = None,
    ) -> None:
        self._heartbeats: dict[str, NodeHeartbeat] = {
            h.node_id: h for h in (heartbeats or ())
        }
        self._epochs: list[EpochSummary] = list(epoch_summaries or ())

    def add_heartbeat(self, hb: NodeHeartbeat) -> None:
        # Last writer wins per node.
        self._heartbeats[hb.node_id] = hb

    def add_epoch(self, summary: EpochSummary) -> None:
        # Replace any prior summary for the same epoch.
        self._epochs = [e for e in self._epochs if e.epoch != summary.epoch]
        self._epochs.append(summary)

    def heartbeats(self) -> list[NodeHeartbeat]:
        return [self._heartbeats[k] for k in sorted(self._heartbeats)]

    def recent_epochs(self, *, limit: int = 10) -> list[EpochSummary]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit out of bounds")
        ordered = sorted(self._epochs, key=lambda e: e.epoch, reverse=True)
        return ordered[:limit]
