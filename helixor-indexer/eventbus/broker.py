"""
eventbus/broker.py — the message-broker abstraction + an in-memory Kafka model.

The Helixor pipeline talks to a broker through the `MessageBroker`
interface. Two implementations:

  - `InMemoryBroker` — a FAITHFUL in-memory model of Kafka: partitioned
    topics, monotonic per-partition offsets, consumer groups with
    independent committed offsets, at-least-once redelivery of uncommitted
    records. Not a toy — it models exactly the semantics the done-when
    tests depend on ("kill a consumer mid-stream, lose nothing").
  - `ConfluentKafkaBroker` (eventbus/confluent_adapter.py) — the production
    adapter over `confluent-kafka`.

Both satisfy `MessageBroker`, so the producer and consumer never know
which broker is underneath.

KAFKA SEMANTICS MODELLED
------------------------
  * A topic has N partitions; a record's `key` hashes to a partition, so
    same-key records keep their relative order.
  * Each partition is an append-only log with monotonic integer offsets.
  * A CONSUMER GROUP has, per partition, a COMMITTED offset (the last
    position the group acknowledged) and — per active consumer — a
    POSITION (how far that consumer has read ahead, uncommitted).
  * A consumer reads from its position; it COMMITS to advance the group's
    committed offset. On a crash, uncommitted records (position >
    committed) are redelivered to the next consumer — at-least-once.
  * Partitions within a group are assigned to consumers; a consumer
    leaving triggers reassignment of its partitions.
"""

from __future__ import annotations

import hashlib
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from eventbus.types import (
    ConsumedRecord,
    DeliveryError,
    EventRecord,
    TopicPartition,
)


# =============================================================================
# MessageBroker — the interface
# =============================================================================

@runtime_checkable
class MessageBroker(Protocol):
    """The broker interface the producer and consumer use."""

    def create_topic(self, topic: str, partitions: int) -> None: ...

    def produce(self, topic: str, record: EventRecord) -> int:
        """Append a record; returns the offset it was written at."""
        ...

    def join_group(self, topic: str, group: str, consumer_id: str) -> set[int]:
        """A consumer joins a group; returns its assigned partitions."""
        ...

    def leave_group(self, topic: str, group: str, consumer_id: str) -> None:
        """A consumer leaves; its uncommitted reads roll back."""
        ...

    def poll(
        self, topic: str, group: str, consumer_id: str, max_records: int,
    ) -> list[ConsumedRecord]:
        """Fetch up to `max_records` from the group's assigned partitions."""
        ...

    def commit(
        self, topic: str, group: str, offsets: dict[int, int],
    ) -> None:
        """Commit the group's offsets — advance the durable read position."""
        ...


# =============================================================================
# Partition — an append-only log
# =============================================================================

class _Partition:
    """One partition: an append-only list of records with integer offsets."""

    __slots__ = ("records",)

    def __init__(self) -> None:
        self.records: list[EventRecord] = []

    def append(self, record: EventRecord) -> int:
        offset = len(self.records)
        self.records.append(record)
        return offset

    @property
    def high_watermark(self) -> int:
        """The offset the next appended record will receive."""
        return len(self.records)


# =============================================================================
# Consumer-group state
# =============================================================================

class _GroupState:
    """
    A consumer group's view of one topic: committed offsets + per-consumer
    read positions + the partition assignment.
    """

    __slots__ = ("committed", "position", "assignment")

    def __init__(self) -> None:
        # partition -> last committed offset (durable; survives a crash).
        self.committed: dict[int, int] = defaultdict(int)
        # partition -> current read position (how far a consumer has read
        # ahead; reset to `committed` when a consumer is reassigned).
        self.position: dict[int, int] = defaultdict(int)
        # consumer_id -> set of partitions it owns.
        self.assignment: dict[str, set[int]] = {}


# =============================================================================
# InMemoryBroker — the faithful Kafka model
# =============================================================================

class InMemoryBroker:
    """
    A faithful in-memory `MessageBroker`. Thread-safe. Models partitions,
    offsets, consumer groups, and at-least-once redelivery.
    """

    def __init__(self, default_partitions: int = 4) -> None:
        self._default_partitions = default_partitions
        self._topics: dict[str, list[_Partition]] = {}
        # topic -> group -> _GroupState
        self._groups: dict[str, dict[str, _GroupState]] = defaultdict(dict)
        self._lock = threading.RLock()

    # ── Topic management ────────────────────────────────────────────────────

    def create_topic(self, topic: str, partitions: int | None = None) -> None:
        with self._lock:
            if topic in self._topics:
                return
            n = partitions if partitions is not None else self._default_partitions
            if n < 1:
                raise ValueError(f"topic needs >= 1 partition, got {n}")
            self._topics[topic] = [_Partition() for _ in range(n)]

    def _ensure_topic(self, topic: str) -> list[_Partition]:
        if topic not in self._topics:
            self.create_topic(topic)
        return self._topics[topic]

    def partition_count(self, topic: str) -> int:
        with self._lock:
            return len(self._ensure_topic(topic))

    # ── Produce ─────────────────────────────────────────────────────────────

    def produce(self, topic: str, record: EventRecord) -> int:
        """
        Append `record` to the partition its key hashes to. Returns the
        offset. Same key → same partition → preserved per-key order.
        """
        with self._lock:
            partitions = self._ensure_topic(topic)
            idx = self._partition_for(record.key, len(partitions))
            return partitions[idx].append(record)

    @staticmethod
    def _partition_for(key: str, partition_count: int) -> int:
        """Deterministic key → partition mapping (stable hash)."""
        digest = hashlib.sha256(key.encode("utf-8")).digest()
        return int.from_bytes(digest[:4], "big") % partition_count

    # ── Consumer-group assignment ───────────────────────────────────────────

    def join_group(self, topic: str, group: str, consumer_id: str) -> set[int]:
        """
        A consumer joins a group on a topic. Returns the partitions it is
        assigned. Rebalances: all partitions are spread across all current
        consumers as evenly as possible.
        """
        with self._lock:
            self._ensure_topic(topic)
            state = self._group_state(topic, group)
            if consumer_id not in state.assignment:
                state.assignment[consumer_id] = set()
            self._rebalance(topic, group)
            return set(state.assignment[consumer_id])

    def leave_group(self, topic: str, group: str, consumer_id: str) -> None:
        """
        A consumer leaves (graceful shutdown OR crash). Its partitions are
        reassigned; their read positions reset to the group's COMMITTED
        offset — so any records the dead consumer read but did not commit
        are redelivered. This is the at-least-once guarantee.
        """
        with self._lock:
            state = self._group_state(topic, group)
            if consumer_id not in state.assignment:
                return
            orphaned = state.assignment.pop(consumer_id)
            # Uncommitted reads on the orphaned partitions are rolled back.
            for partition in orphaned:
                state.position[partition] = state.committed[partition]
            self._rebalance(topic, group)

    def _rebalance(self, topic: str, group: str) -> None:
        """Spread all partitions evenly across the group's live consumers."""
        state = self._group_state(topic, group)
        consumers = sorted(state.assignment)
        if not consumers:
            return
        partition_count = len(self._topics[topic])
        # Clear, then round-robin assign.
        for cid in consumers:
            state.assignment[cid] = set()
        for partition in range(partition_count):
            owner = consumers[partition % len(consumers)]
            state.assignment[owner].add(partition)

    # ── Poll ────────────────────────────────────────────────────────────────

    def poll(
        self, topic: str, group: str, consumer_id: str, max_records: int,
    ) -> list[ConsumedRecord]:
        """
        Fetch up to `max_records` for `consumer_id` from the partitions it
        owns, starting at each partition's current read position. Advances
        the in-memory position (NOT the committed offset — that needs an
        explicit commit).
        """
        with self._lock:
            partitions = self._ensure_topic(topic)
            state = self._group_state(topic, group)
            owned = sorted(state.assignment.get(consumer_id, set()))
            if not owned:
                raise DeliveryError(
                    f"consumer {consumer_id} owns no partitions in group "
                    f"{group} on {topic} — did it join_group?"
                )

            out: list[ConsumedRecord] = []
            for partition in owned:
                pos = state.position[partition]
                log = partitions[partition].records
                while pos < len(log) and len(out) < max_records:
                    out.append(ConsumedRecord(
                        topic=topic, partition=partition, offset=pos,
                        record=log[pos],
                    ))
                    pos += 1
                state.position[partition] = pos
                if len(out) >= max_records:
                    break
            return out

    # ── Commit ──────────────────────────────────────────────────────────────

    def commit(
        self, topic: str, group: str, offsets: dict[int, int],
    ) -> None:
        """
        Commit `offsets` (partition -> next-offset-to-read) for the group.
        A committed offset is durable: a crash rolls back to it, not past it.
        """
        with self._lock:
            state = self._group_state(topic, group)
            for partition, offset in offsets.items():
                # Commit is monotonic — never moves backwards.
                if offset > state.committed[partition]:
                    state.committed[partition] = offset

    def seek_to_committed(
        self, topic: str, group: str, partitions: set[int],
    ) -> None:
        """
        Rewind the read position of the given partitions to the group's
        committed offset — Kafka's `seek`. The consumer uses this to
        REDELIVER records it polled but did not commit (a transient
        processing failure that should be retried), without a full
        leave/rejoin.
        """
        with self._lock:
            state = self._group_state(topic, group)
            for partition in partitions:
                state.position[partition] = state.committed[partition]

    # ── Introspection (tests / monitoring) ──────────────────────────────────

    def committed_offset(self, topic: str, group: str, partition: int) -> int:
        with self._lock:
            return self._group_state(topic, group).committed[partition]

    def high_watermark(self, topic: str, partition: int) -> int:
        with self._lock:
            return self._ensure_topic(topic)[partition].high_watermark

    def total_records(self, topic: str) -> int:
        with self._lock:
            return sum(p.high_watermark for p in self._ensure_topic(topic))

    def all_records(self, topic: str) -> list[EventRecord]:
        """Every record on the topic, across partitions — for assertions."""
        with self._lock:
            out: list[EventRecord] = []
            for partition in self._ensure_topic(topic):
                out.extend(partition.records)
            return out

    def _group_state(self, topic: str, group: str) -> _GroupState:
        groups = self._groups[topic]
        if group not in groups:
            groups[group] = _GroupState()
        return groups[group]
