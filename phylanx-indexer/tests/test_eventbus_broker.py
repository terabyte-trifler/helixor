"""
tests/test_eventbus_broker.py — the in-memory Kafka broker model.

The InMemoryBroker is a FAITHFUL model of Kafka — the done-when tests
depend on it modelling offsets, consumer groups, and at-least-once
redelivery exactly. These tests pin that fidelity down.
"""

from __future__ import annotations

import pytest

from eventbus.broker import InMemoryBroker, MessageBroker
from eventbus.types import DeliveryError, EventRecord


def _rec(key: str, value: str) -> EventRecord:
    return EventRecord(key=key, value=value.encode("utf-8"))


# =============================================================================
# Topics + partitions
# =============================================================================

class TestTopics:

    def test_satisfies_broker_protocol(self):
        assert isinstance(InMemoryBroker(), MessageBroker)

    def test_create_topic(self):
        broker = InMemoryBroker()
        broker.create_topic("t", 4)
        assert broker.partition_count("t") == 4

    def test_create_topic_idempotent(self):
        broker = InMemoryBroker()
        broker.create_topic("t", 4)
        broker.create_topic("t", 8)          # second call is a no-op
        assert broker.partition_count("t") == 4

    def test_produce_auto_creates_topic(self):
        broker = InMemoryBroker(default_partitions=2)
        broker.produce("auto", _rec("k", "v"))
        assert broker.partition_count("auto") == 2

    def test_topic_needs_at_least_one_partition(self):
        broker = InMemoryBroker()
        with pytest.raises(ValueError):
            broker.create_topic("t", 0)


# =============================================================================
# Partitioning — same key, same partition
# =============================================================================

class TestPartitioning:

    def test_same_key_same_partition(self):
        broker = InMemoryBroker(default_partitions=8)
        broker.create_topic("t", 8)
        # 20 records under one key — all must land on one partition.
        for i in range(20):
            broker.produce("t", _rec("agentA", f"v{i}"))
        non_empty = sum(
            1 for p in range(8)
            if broker.high_watermark("t", p) > 0
        )
        assert non_empty == 1

    def test_different_keys_spread(self):
        broker = InMemoryBroker(default_partitions=8)
        broker.create_topic("t", 8)
        for i in range(50):
            broker.produce("t", _rec(f"agent{i}", "v"))
        # 50 distinct keys over 8 partitions — expect several partitions used.
        non_empty = sum(
            1 for p in range(8) if broker.high_watermark("t", p) > 0
        )
        assert non_empty > 1

    def test_partition_assignment_deterministic(self):
        b1, b2 = InMemoryBroker(), InMemoryBroker()
        for b in (b1, b2):
            b.create_topic("t", 8)
            for i in range(30):
                b.produce("t", _rec(f"k{i}", "v"))
        # The two brokers, fed identically, must land records identically.
        for p in range(8):
            assert b1.high_watermark("t", p) == b2.high_watermark("t", p)


# =============================================================================
# Offsets — monotonic, per partition
# =============================================================================

class TestOffsets:

    def test_produce_returns_monotonic_offset(self):
        broker = InMemoryBroker()
        broker.create_topic("t", 1)
        offsets = [broker.produce("t", _rec("k", f"v{i}")) for i in range(5)]
        assert offsets == [0, 1, 2, 3, 4]

    def test_high_watermark_tracks_appends(self):
        broker = InMemoryBroker()
        broker.create_topic("t", 1)
        assert broker.high_watermark("t", 0) == 0
        broker.produce("t", _rec("k", "v"))
        assert broker.high_watermark("t", 0) == 1


# =============================================================================
# Consumer groups + poll
# =============================================================================

class TestConsumerGroups:

    def test_join_assigns_all_partitions_to_lone_consumer(self):
        broker = InMemoryBroker()
        broker.create_topic("t", 8)
        assigned = broker.join_group("t", "g", "c1")
        assert assigned == set(range(8))

    def test_two_consumers_split_partitions(self):
        broker = InMemoryBroker()
        broker.create_topic("t", 8)
        broker.join_group("t", "g", "c1")
        broker.join_group("t", "g", "c2")
        # After c2 joins, partitions are rebalanced across both.
        a1 = broker.join_group("t", "g", "c1")   # re-fetch assignment
        a2 = broker.join_group("t", "g", "c2")
        assert a1 | a2 == set(range(8))
        assert a1 & a2 == set()                  # no overlap
        assert len(a1) == 4 and len(a2) == 4

    def test_poll_returns_produced_records(self):
        broker = InMemoryBroker()
        broker.create_topic("t", 1)
        broker.produce("t", _rec("k", "v0"))
        broker.produce("t", _rec("k", "v1"))
        broker.join_group("t", "g", "c1")
        batch = broker.poll("t", "g", "c1", max_records=10)
        assert len(batch) == 2

    def test_poll_advances_position(self):
        broker = InMemoryBroker()
        broker.create_topic("t", 1)
        broker.produce("t", _rec("k", "v0"))
        broker.join_group("t", "g", "c1")
        first = broker.poll("t", "g", "c1", max_records=10)
        second = broker.poll("t", "g", "c1", max_records=10)
        assert len(first) == 1
        assert len(second) == 0                  # already read

    def test_poll_without_join_raises(self):
        broker = InMemoryBroker()
        broker.create_topic("t", 1)
        broker.produce("t", _rec("k", "v"))
        with pytest.raises(DeliveryError):
            broker.poll("t", "g", "never_joined", max_records=10)

    def test_poll_respects_max_records(self):
        broker = InMemoryBroker()
        broker.create_topic("t", 1)
        for i in range(10):
            broker.produce("t", _rec("k", f"v{i}"))
        broker.join_group("t", "g", "c1")
        batch = broker.poll("t", "g", "c1", max_records=3)
        assert len(batch) == 3


# =============================================================================
# Commit + the at-least-once redelivery guarantee
# =============================================================================

class TestCommitAndRedelivery:

    def test_commit_advances_committed_offset(self):
        broker = InMemoryBroker()
        broker.create_topic("t", 1)
        broker.produce("t", _rec("k", "v"))
        broker.join_group("t", "g", "c1")
        broker.poll("t", "g", "c1", max_records=10)
        broker.commit("t", "g", {0: 1})
        assert broker.committed_offset("t", "g", 0) == 1

    def test_commit_is_monotonic(self):
        broker = InMemoryBroker()
        broker.create_topic("t", 1)
        broker.join_group("t", "g", "c1")
        broker.commit("t", "g", {0: 5})
        broker.commit("t", "g", {0: 2})          # backwards — ignored
        assert broker.committed_offset("t", "g", 0) == 5

    def test_uncommitted_reads_redeliver_on_leave(self):
        # THE AT-LEAST-ONCE CORE: a consumer polls records but does NOT
        # commit, then leaves (crash). The records must be redeliverable.
        broker = InMemoryBroker()
        broker.create_topic("t", 1)
        for i in range(5):
            broker.produce("t", _rec("k", f"v{i}"))

        broker.join_group("t", "g", "c1")
        polled = broker.poll("t", "g", "c1", max_records=5)
        assert len(polled) == 5
        # c1 crashes WITHOUT committing.
        broker.leave_group("t", "g", "c1")

        # c2 takes over — it must see all 5 again (nothing committed).
        broker.join_group("t", "g", "c2")
        redelivered = broker.poll("t", "g", "c2", max_records=5)
        assert len(redelivered) == 5

    def test_committed_records_not_redelivered(self):
        # A consumer that DID commit — the committed records do NOT
        # redeliver to its successor.
        broker = InMemoryBroker()
        broker.create_topic("t", 1)
        for i in range(5):
            broker.produce("t", _rec("k", f"v{i}"))

        broker.join_group("t", "g", "c1")
        broker.poll("t", "g", "c1", max_records=3)
        broker.commit("t", "g", {0: 3})          # commit first 3
        broker.leave_group("t", "g", "c1")

        broker.join_group("t", "g", "c2")
        redelivered = broker.poll("t", "g", "c2", max_records=10)
        # Only the 2 uncommitted records redeliver.
        assert len(redelivered) == 2

    def test_seek_to_committed_rewinds_position(self):
        broker = InMemoryBroker()
        broker.create_topic("t", 1)
        for i in range(5):
            broker.produce("t", _rec("k", f"v{i}"))
        broker.join_group("t", "g", "c1")
        broker.poll("t", "g", "c1", max_records=5)     # position now 5
        broker.seek_to_committed("t", "g", {0})        # rewind to committed (0)
        again = broker.poll("t", "g", "c1", max_records=5)
        assert len(again) == 5                          # re-read everything
