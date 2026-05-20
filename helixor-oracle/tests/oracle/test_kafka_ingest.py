"""
tests/oracle/test_kafka_ingest.py — Day-17 bus -> Day-23 cluster bridge.

Pins the deterministic batching of bus events into per-agent batches: the
ingest layer is what makes the in-memory broker (deterministic) replay
straight into the cluster (also deterministic), end to end.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from oracle.cluster.kafka_ingest import (
    IngestedAgentBatch,
    batch_transactions_by_agent,
)


# A minimal Transaction shape that matches what the real type carries —
# what the sort key uses (block_time + signature) and the agent_wallet.
# This keeps the test self-contained even if the feature-extractor moves.
@dataclass(frozen=True, slots=True)
class _FakeTxn:
    agent_wallet: str
    block_time:   int
    signature:    str = ""


def _window():
    # Minimal ExtractionWindow stand-in via a duck type — the batcher
    # never reads its fields, just attaches it to each batch.
    return object()


# =============================================================================
# Batching
# =============================================================================

class TestBatchTransactionsByAgent:

    def test_empty_input_yields_no_batches(self):
        batches = batch_transactions_by_agent([], window=_window())
        assert batches == []

    def test_one_agent_one_batch(self):
        txns = [_FakeTxn("agentA", 100), _FakeTxn("agentA", 200)]
        batches = batch_transactions_by_agent(txns, window=_window())
        assert len(batches) == 1
        assert batches[0].agent_wallet == "agentA"
        assert batches[0].transaction_count == 2

    def test_multiple_agents_separate_batches(self):
        txns = [
            _FakeTxn("agentB", 100),
            _FakeTxn("agentA", 200),
            _FakeTxn("agentB", 150),
            _FakeTxn("agentA", 50),
        ]
        batches = batch_transactions_by_agent(txns, window=_window())
        assert len(batches) == 2
        # Sorted by wallet for deterministic order.
        assert [b.agent_wallet for b in batches] == ["agentA", "agentB"]
        assert batches[0].transaction_count == 2
        assert batches[1].transaction_count == 2

    def test_transactions_in_each_batch_are_chronologically_sorted(self):
        # The feature extractor expects canonical-order transactions —
        # the batcher sorts by (block_time, signature) so a replayed
        # bus produces deterministic input regardless of arrival order.
        txns = [
            _FakeTxn("agentA", 300, "sig3"),
            _FakeTxn("agentA", 100, "sig1"),
            _FakeTxn("agentA", 200, "sig2"),
        ]
        batches = batch_transactions_by_agent(txns, window=_window())
        sigs = [t.signature for t in batches[0].transactions]
        assert sigs == ["sig1", "sig2", "sig3"]

    def test_same_timestamp_broken_by_signature(self):
        # Two transactions with the same block_time must still order
        # deterministically — the signature is the secondary sort key.
        txns = [
            _FakeTxn("agentA", 100, "sigZ"),
            _FakeTxn("agentA", 100, "sigA"),
        ]
        batches = batch_transactions_by_agent(txns, window=_window())
        assert [t.signature for t in batches[0].transactions] == ["sigA", "sigZ"]

    def test_batching_is_deterministic(self):
        # Same input -> same batches, byte-for-byte. This is the property
        # that lets in-memory broker replays reproduce a cluster epoch.
        txns = [
            _FakeTxn("agentB", 100, "x"),
            _FakeTxn("agentA", 200, "y"),
            _FakeTxn("agentB", 150, "z"),
        ]
        a = batch_transactions_by_agent(txns, window=_window())
        b = batch_transactions_by_agent(txns, window=_window())
        assert [x.agent_wallet for x in a] == [x.agent_wallet for x in b]
        assert [[t.signature for t in batch.transactions] for batch in a] == \
               [[t.signature for t in batch.transactions] for batch in b]


# =============================================================================
# IngestedAgentBatch shape
# =============================================================================

class TestIngestedAgentBatch:

    def test_carries_agent_window_and_transactions(self):
        window = _window()
        txns = [_FakeTxn("agentA", 100)]
        batches = batch_transactions_by_agent(txns, window=window)
        batch = batches[0]
        assert batch.agent_wallet == "agentA"
        assert batch.window is window
        assert isinstance(batch.transactions, tuple)
        assert batch.transactions[0].agent_wallet == "agentA"


# =============================================================================
# Replay-from-broker honest scope
# =============================================================================

class TestReplayFromBroker:

    def test_empty_broker_returns_empty(self):
        # When eventbus.serialization is not importable from the oracle
        # stack (the test environment), replay falls back to []. This
        # asserts the function is robust to that — it never raises.
        from oracle.cluster.kafka_ingest import replay_from_broker

        class _BrokerStub:
            def join_group(self, *a, **kw):
                return {0}
            def poll(self, *a, **kw):
                return []
            def commit(self, *a, **kw):
                pass

        result = replay_from_broker(_BrokerStub())
        assert isinstance(result, list)
        assert result == []
