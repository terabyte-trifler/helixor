"""
tests/test_vuln14_cert_gate.py — pin tests for the oracle.lag_gate cert interlock.

These tests sit on the INDEXER side because the indexer's conftest already
puts both `phylanx-indexer/` (for `eventbus`) and `phylanx-oracle/` (for
`oracle.lag_gate`) on sys.path — the exact deployment shape the gate
lives in. The gate is the audit-mandated "scoring engine refuses to
issue new certs until caught up" — these tests pin the refusal
behaviour and the success behaviour.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from eventbus import ConsumerLagMonitor, EventRecord, InMemoryBroker
from oracle.lag_gate import (
    CertBlocked,
    ConsumerLagExceeded,
    LagGatedSubmit,
)


# The agent_profiles helper used by the run_epoch integration test lives
# in phylanx-oracle's test tree (phylanx-oracle/tests/oracle/agent_profiles.py).
# Pytest's auto-discovery binds `tests` to the indexer's own tests package,
# so we cannot do `from tests.oracle.agent_profiles import ...`. Side-load
# the file directly via importlib instead.
def _load_agent_profiles():
    profiles_path = (
        Path(__file__).resolve().parent.parent.parent
        / "phylanx-oracle" / "tests" / "oracle" / "agent_profiles.py"
    )
    spec = importlib.util.spec_from_file_location(
        "vuln14_agent_profiles", profiles_path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# =============================================================================
# Helpers
# =============================================================================

def _make_broker(per_partition: dict[int, int], *, topic: str, group: str):
    """Build a broker with N records on each partition, none committed."""
    broker = InMemoryBroker(default_partitions=4)
    broker.create_topic(topic, 4)
    for p, n in per_partition.items():
        log = broker._topics[topic][p]                       # noqa: SLF001
        for i in range(n):
            log.append(EventRecord(key=f"p{p}-{i}", value=b"x"))
    broker.join_group(topic, group, "test-consumer")
    return broker


class _StubScoreResult:
    """A minimal stand-in for ScoreResult — the gate never inspects it."""

    def __init__(self, score: int = 700) -> None:
        self.score = score


def _recording_submit():
    """A SubmitFn that records every call — the inner cert-write seam."""
    calls: list[tuple[str, int]] = []

    def _inner(wallet: str, score_result) -> dict:
        calls.append((wallet, score_result.score))
        return {"wallet": wallet, "score": score_result.score}

    return _inner, calls


# =============================================================================
# Happy path — gate is transparent when lag is under threshold
# =============================================================================

class TestGateAllowsWhenCaughtUp:

    def test_allows_when_no_lag(self):
        broker = _make_broker({0: 0, 1: 0, 2: 0, 3: 0},
                              topic="agent.cert_events", group="oracle-cert")
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=100)
        inner, calls = _recording_submit()
        gate = LagGatedSubmit(inner, monitor=monitor)

        result = gate("agent1", _StubScoreResult(700))

        assert calls == [("agent1", 700)]
        assert result == {"wallet": "agent1", "score": 700}

    def test_allows_under_threshold_and_returns_inner_result(self):
        broker = _make_broker({0: 5, 1: 0, 2: 0, 3: 0},
                              topic="agent.cert_events", group="oracle-cert")
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=100)
        inner, calls = _recording_submit()
        gate = LagGatedSubmit(inner, monitor=monitor)

        gate("agent1", _StubScoreResult(700))
        gate("agent2", _StubScoreResult(800))

        assert calls == [("agent1", 700), ("agent2", 800)]


# =============================================================================
# Block path — gate refuses cert when lag exceeds either cap
# =============================================================================

class TestGateBlocksWhenLagExceeded:

    def test_raises_when_partition_lag_over_cap(self):
        broker = _make_broker({0: 100, 1: 0, 2: 0, 3: 0},
                              topic="agent.cert_events", group="oracle-cert")
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=10000)
        inner, calls = _recording_submit()
        gate = LagGatedSubmit(inner, monitor=monitor)

        with pytest.raises(ConsumerLagExceeded) as excinfo:
            gate("agent1", _StubScoreResult(700))

        assert excinfo.value.agent_wallet == "agent1"
        assert excinfo.value.snapshot.within_threshold is False
        # Crucially the inner cert-write was NEVER called — no stale cert
        # leaked through.
        assert calls == []

    def test_raises_when_total_lag_over_cap(self):
        broker = _make_broker({0: 9, 1: 9, 2: 9, 3: 9},
                              topic="agent.cert_events", group="oracle-cert")
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=20)
        inner, calls = _recording_submit()
        gate = LagGatedSubmit(inner, monitor=monitor)

        with pytest.raises(ConsumerLagExceeded):
            gate("agent1", _StubScoreResult(700))

        assert calls == []                                  # inner never invoked

    def test_exception_message_mentions_vuln14(self):
        # The exception text ends up on logs / postmortems; pinning so an
        # operator searching for "VULN-14" lands on the blocked-cert line.
        broker = _make_broker({0: 100}, topic="agent.cert_events", group="oracle-cert")
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=10000)
        gate = LagGatedSubmit(_recording_submit()[0], monitor=monitor)

        with pytest.raises(ConsumerLagExceeded) as excinfo:
            gate("agent1", _StubScoreResult())
        assert "VULN-14" in str(excinfo.value)


# =============================================================================
# Observer side-channel — Prometheus / pager seam
# =============================================================================

class TestObserver:

    def test_observer_fires_on_block_with_snapshot(self):
        broker = _make_broker({0: 100}, topic="agent.cert_events", group="oracle-cert")
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=10000)
        events: list[CertBlocked] = []
        gate = LagGatedSubmit(
            _recording_submit()[0], monitor=monitor,
            observer=events.append,
        )

        with pytest.raises(ConsumerLagExceeded):
            gate("agent1", _StubScoreResult())

        assert len(events) == 1
        assert events[0].agent_wallet == "agent1"
        assert events[0].snapshot.within_threshold is False
        assert events[0].snapshot.topic == "agent.cert_events"

    def test_observer_does_not_fire_on_success(self):
        broker = _make_broker({0: 0}, topic="agent.cert_events", group="oracle-cert")
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=10000)
        events: list[CertBlocked] = []
        gate = LagGatedSubmit(
            _recording_submit()[0], monitor=monitor,
            observer=events.append,
        )

        gate("agent1", _StubScoreResult())

        assert events == []


# =============================================================================
# Integration with run_epoch's submit_fn seam
# =============================================================================

class TestRunEpochIntegration:
    """
    The gate is a drop-in `SubmitFn` for `oracle.epoch_runner.run_epoch`.
    The runner's existing per-agent try/except around `submit_fn` must
    catch `ConsumerLagExceeded` and produce a result with the cert
    NOT submitted and an error message — without aborting the epoch.
    """

    def test_run_epoch_records_blocked_cert_as_error_and_continues(self):
        from datetime import datetime, timezone

        from oracle.epoch_runner import run_epoch
        ALL_PROFILES = _load_agent_profiles().ALL_PROFILES

        REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)

        # A broker with overwhelming lag → gate refuses every cert.
        broker = _make_broker(
            {0: 100, 1: 100, 2: 100, 3: 100},
            topic="agent.cert_events", group="oracle-cert",
        )
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=20)
        inner, inner_calls = _recording_submit()
        gate = LagGatedSubmit(inner, monitor=monitor)

        inputs = [gen() for gen, _ in ALL_PROFILES.values()]
        report = run_epoch(
            epoch_id=14, agent_inputs=inputs,
            submit_fn=gate, computed_at=REF_END,
        )

        # Every agent was SCORED (the score path is independent of the gate).
        assert report.agent_count == 8
        for r in report.results:
            assert r.score_result is not None
        # But NONE was submitted — the gate refused every cert.
        assert report.submitted_count == 0
        # Every result carries the VULN-14 error.
        for r in report.results:
            assert r.submitted is False
            assert "submission failed" in r.error
            assert "VULN-14" in r.error
        # The inner cert-write seam was NEVER called.
        assert inner_calls == []

    def test_run_epoch_passes_certs_when_lag_under_threshold(self):
        from datetime import datetime, timezone

        from oracle.epoch_runner import run_epoch
        ALL_PROFILES = _load_agent_profiles().ALL_PROFILES

        REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)

        broker = _make_broker(
            {0: 0, 1: 0, 2: 0, 3: 0},
            topic="agent.cert_events", group="oracle-cert",
        )
        monitor = ConsumerLagMonitor(broker, max_partition_lag=10, max_total_lag=20)
        inner, inner_calls = _recording_submit()
        gate = LagGatedSubmit(inner, monitor=monitor)

        inputs = [gen() for gen, _ in ALL_PROFILES.values()]
        report = run_epoch(
            epoch_id=14, agent_inputs=inputs,
            submit_fn=gate, computed_at=REF_END,
        )

        # All 8 certs submitted; the gate was transparent.
        assert report.submitted_count == 8
        assert len(inner_calls) == 8
        for r in report.results:
            assert r.error == ""
