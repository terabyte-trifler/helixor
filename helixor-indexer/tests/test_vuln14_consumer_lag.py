"""
tests/test_vuln14_consumer_lag.py — pin tests for VULN-14 consumer-lag awareness.

VULN-14 inserts a consumer-lag interlock between the scoring engine and
the on-chain cert path. The audit's worry: an attacker who can inflate
publish rate can drive the consumer-group backlog past the epoch
boundary, leaving the oracle to issue GREEN certs against PRE-spike
data — a stale scoring window. The fix is a `ConsumerLagMonitor` that
measures records-behind per (topic, group) against operator-configured
thresholds; the cert path (oracle.lag_gate) consults the monitor and
REFUSES TO ISSUE a cert when lag exceeds the threshold.

These tests pin the monitor's pure behaviour against `InMemoryBroker`
— the faithful Kafka model the rest of the suite already trusts.
"""

from __future__ import annotations

import os

import pytest

from eventbus import (
    BrokerIntrospector,
    ConsumerLagMonitor,
    EventRecord,
    InMemoryBroker,
    LagSnapshot,
    Topic,
)
from eventbus.lag_monitor import (
    DEFAULT_MAX_PARTITION_LAG,
    DEFAULT_MAX_TOTAL_LAG,
)


# =============================================================================
# Helpers
# =============================================================================

def _make_broker_with_lag(
    topic: str,
    group: str,
    per_partition: dict[int, int],
    *,
    partitions: int = 4,
) -> InMemoryBroker:
    """
    Build a broker with `per_partition[p]` records produced on partition `p`
    and 0 committed for `group`, so observed lag == per_partition[p].

    We bypass the producer's hash-to-partition by appending directly via
    the broker's internal partition list — the only way to deterministically
    place N records on a specific partition.
    """
    broker = InMemoryBroker(default_partitions=partitions)
    broker.create_topic(topic, partitions)
    # Reach into the broker's partition list directly so we can place
    # records deterministically per partition (the producer's key->partition
    # hash makes that hard to do via produce()).
    for p, n in per_partition.items():
        log = broker._topics[topic][p]                       # noqa: SLF001
        for i in range(n):
            log.append(EventRecord(key=f"p{p}-{i}", value=b"x"))
    # Ensure the group exists with committed=0 for every partition.
    broker.join_group(topic, group, "test-consumer")
    return broker


# =============================================================================
# BrokerIntrospector — Protocol conformance
# =============================================================================

class TestBrokerIntrospector:

    def test_in_memory_broker_satisfies_introspector_protocol(self):
        # InMemoryBroker must be usable as a BrokerIntrospector without
        # adapter — that is the audit-mandated zero-coupling guarantee.
        assert isinstance(InMemoryBroker(), BrokerIntrospector)


# =============================================================================
# Default thresholds — operator-tunable, sensible defaults
# =============================================================================

class TestDefaultThresholds:

    def test_defaults_are_published_constants(self):
        # The defaults are part of the public contract — operators read
        # them, alerts cite them, and SECOPS tests pin them.
        assert DEFAULT_MAX_PARTITION_LAG == 500
        assert DEFAULT_MAX_TOTAL_LAG == 4_000

    def test_monitor_falls_back_to_defaults(self):
        monitor = ConsumerLagMonitor(InMemoryBroker())
        assert monitor.max_partition_lag == DEFAULT_MAX_PARTITION_LAG
        assert monitor.max_total_lag == DEFAULT_MAX_TOTAL_LAG

    def test_explicit_args_override_defaults(self):
        monitor = ConsumerLagMonitor(
            InMemoryBroker(), max_partition_lag=10, max_total_lag=100,
        )
        assert monitor.max_partition_lag == 10
        assert monitor.max_total_lag == 100

    def test_env_overrides_defaults(self, monkeypatch):
        monkeypatch.setenv("HELIXOR_CONSUMER_LAG_MAX_PARTITION", "77")
        monkeypatch.setenv("HELIXOR_CONSUMER_LAG_MAX_TOTAL", "999")
        monitor = ConsumerLagMonitor(InMemoryBroker())
        assert monitor.max_partition_lag == 77
        assert monitor.max_total_lag == 999

    def test_explicit_arg_beats_env(self, monkeypatch):
        # Constructor args MUST win over env vars; deployments override per
        # cluster, tests override per case.
        monkeypatch.setenv("HELIXOR_CONSUMER_LAG_MAX_PARTITION", "77")
        monitor = ConsumerLagMonitor(InMemoryBroker(), max_partition_lag=42)
        assert monitor.max_partition_lag == 42

    def test_garbage_env_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("HELIXOR_CONSUMER_LAG_MAX_PARTITION", "not-a-number")
        monitor = ConsumerLagMonitor(InMemoryBroker())
        assert monitor.max_partition_lag == DEFAULT_MAX_PARTITION_LAG

    def test_negative_env_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("HELIXOR_CONSUMER_LAG_MAX_TOTAL", "-5")
        monitor = ConsumerLagMonitor(InMemoryBroker())
        assert monitor.max_total_lag == DEFAULT_MAX_TOTAL_LAG

    def test_negative_explicit_arg_raises(self):
        with pytest.raises(ValueError):
            ConsumerLagMonitor(InMemoryBroker(), max_partition_lag=-1)
        with pytest.raises(ValueError):
            ConsumerLagMonitor(InMemoryBroker(), max_total_lag=-1)


# =============================================================================
# CERT_EVENTS topic — VULN-14 topic isolation
# =============================================================================

class TestCertEventsTopicIsolation:

    def test_cert_events_topic_exists_and_is_isolated(self):
        # The audit asks for "Kafka topic isolation: separate high-priority
        # cert topics from general telemetry". The dedicated topic value is
        # the contract operators read.
        assert Topic.CERT_EVENTS.value == "agent.cert_events"
        # Distinct from every other topic — otherwise isolation is in name only.
        all_values = {t.value for t in Topic}
        assert len(all_values) == len({
            Topic.TRANSACTIONS.value, Topic.ALERTS.value,
            Topic.DEAD_LETTER.value, Topic.CERT_EVENTS.value,
        })


# =============================================================================
# lag_by_partition — the core measurement
# =============================================================================

class TestLagByPartition:

    def test_zero_records_zero_lag(self):
        broker = _make_broker_with_lag("t", "g", {0: 0, 1: 0, 2: 0, 3: 0})
        monitor = ConsumerLagMonitor(broker)
        assert monitor.lag_by_partition("t", "g") == {0: 0, 1: 0, 2: 0, 3: 0}

    def test_uncommitted_records_show_full_lag(self):
        broker = _make_broker_with_lag("t", "g", {0: 7, 1: 3, 2: 0, 3: 11})
        monitor = ConsumerLagMonitor(broker)
        assert monitor.lag_by_partition("t", "g") == {0: 7, 1: 3, 2: 0, 3: 11}

    def test_committed_offsets_subtract_from_lag(self):
        broker = _make_broker_with_lag("t", "g", {0: 10})
        broker.commit("t", "g", {0: 4})
        monitor = ConsumerLagMonitor(broker)
        # 10 produced, 4 committed → 6 remaining.
        assert monitor.lag_by_partition("t", "g")[0] == 6

    def test_lag_clamps_at_zero(self):
        # If committed > high_watermark for some reason (it should not, but
        # the monitor must not return negative lag — that would silently
        # subtract from total and bypass the cap).
        broker = _make_broker_with_lag("t", "g", {0: 5})
        broker.commit("t", "g", {0: 99})            # absurd over-commit
        monitor = ConsumerLagMonitor(broker)
        assert monitor.lag_by_partition("t", "g")[0] == 0

    def test_new_topic_with_no_records_no_group(self):
        # A monitor pointed at a fresh topic + a group that has never read
        # → all partitions read as 0 lag, not as an error.
        broker = InMemoryBroker(default_partitions=4)
        broker.create_topic("t", 4)
        monitor = ConsumerLagMonitor(broker)
        assert monitor.lag_by_partition("t", "fresh-group") == {
            0: 0, 1: 0, 2: 0, 3: 0,
        }


# =============================================================================
# total_lag + max_observed_partition_lag — aggregations
# =============================================================================

class TestAggregations:

    def test_total_lag_sums_partitions(self):
        broker = _make_broker_with_lag("t", "g", {0: 7, 1: 3, 2: 0, 3: 11})
        monitor = ConsumerLagMonitor(broker)
        assert monitor.total_lag("t", "g") == 21

    def test_max_observed_partition_lag(self):
        broker = _make_broker_with_lag("t", "g", {0: 7, 1: 3, 2: 0, 3: 11})
        monitor = ConsumerLagMonitor(broker)
        assert monitor.max_observed_partition_lag("t", "g") == 11

    def test_max_observed_partition_lag_zero_when_caught_up(self):
        broker = _make_broker_with_lag("t", "g", {0: 0, 1: 0, 2: 0, 3: 0})
        monitor = ConsumerLagMonitor(broker)
        assert monitor.max_observed_partition_lag("t", "g") == 0


# =============================================================================
# snapshot.within_threshold — the gate's decision
# =============================================================================

class TestSnapshotThreshold:

    def test_within_threshold_when_caught_up(self):
        broker = _make_broker_with_lag("t", "g", {0: 0, 1: 0, 2: 0, 3: 0})
        monitor = ConsumerLagMonitor(broker, max_partition_lag=100, max_total_lag=100)
        snap = monitor.snapshot("t", "g")
        assert snap.within_threshold is True
        assert snap.total_lag == 0
        assert snap.max_partition_lag == 0
        assert snap.reason() == ""

    def test_within_threshold_at_exact_boundary(self):
        # The cap is inclusive (<=) — pinning so a one-off doesn't push it
        # to strict-less-than and trip on the most common operating point.
        broker = _make_broker_with_lag("t", "g", {0: 10})
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=10)
        snap = monitor.snapshot("t", "g")
        assert snap.within_threshold is True

    def test_blocks_when_partition_lag_exceeded(self):
        broker = _make_broker_with_lag("t", "g", {0: 11, 1: 0, 2: 0, 3: 0})
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=1000)
        snap = monitor.snapshot("t", "g")
        assert snap.within_threshold is False
        assert snap.offending_partitions == (0,)
        assert "per-partition cap" in snap.reason()

    def test_blocks_when_total_lag_exceeded_even_if_partition_ok(self):
        # No SINGLE partition exceeds the per-partition cap, but the SUM
        # does — catches the cluster-wide-backlog case (consumer crash).
        broker = _make_broker_with_lag(
            "t", "g", {0: 9, 1: 9, 2: 9, 3: 9},
        )
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=20)
        snap = monitor.snapshot("t", "g")
        assert snap.within_threshold is False
        assert snap.offending_partitions == ()        # none individually over cap
        assert "total lag" in snap.reason()

    def test_blocks_when_both_exceeded_reports_both(self):
        broker = _make_broker_with_lag("t", "g", {0: 50, 1: 50, 2: 50, 3: 50})
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=20)
        snap = monitor.snapshot("t", "g")
        assert snap.within_threshold is False
        assert "total lag" in snap.reason()
        assert "per-partition cap" in snap.reason()
        # All four partitions are offending.
        assert snap.offending_partitions == (0, 1, 2, 3)

    def test_is_within_threshold_matches_snapshot(self):
        # The fast-path predicate must agree with the snapshot — divergence
        # would let one code path pass certs the other would block.
        broker = _make_broker_with_lag("t", "g", {0: 11})
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=1000)
        assert monitor.is_within_threshold("t", "g") is False
        broker.commit("t", "g", {0: 11})
        assert monitor.is_within_threshold("t", "g") is True


# =============================================================================
# LagSnapshot — dataclass shape stability
# =============================================================================

class TestLagSnapshotShape:

    def test_snapshot_carries_thresholds_used(self):
        # The snapshot must pin the thresholds it was evaluated against so
        # downstream events / pager alerts cite the cap that fired, not the
        # cap that happens to be set when the alert is read.
        broker = _make_broker_with_lag("t", "g", {0: 11})
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=99)
        snap = monitor.snapshot("t", "g")
        assert snap.threshold_partition == 10
        assert snap.threshold_total == 99
        assert snap.topic == "t"
        assert snap.group == "g"
        assert snap.captured_at > 0

    def test_snapshot_is_frozen(self):
        # Snapshots must be immutable — they are passed around as audit
        # evidence and stuffed into exceptions; a downstream mutation would
        # corrupt the postmortem record.
        broker = _make_broker_with_lag("t", "g", {0: 1})
        snap = ConsumerLagMonitor(broker).snapshot("t", "g")
        with pytest.raises((AttributeError, Exception)):
            snap.total_lag = 9999                          # type: ignore[misc]
