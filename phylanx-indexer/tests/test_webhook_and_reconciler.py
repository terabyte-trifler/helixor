"""
tests/test_webhook_and_reconciler.py — the webhook fallback + the reconciler.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from indexer import (
    DivergenceSeverity,
    WebhookReceiver,
    decode_webhook_payload,
    reconcile_agent,
    reconcile_all,
)
from indexer.webhook_fallback import WebhookDecodeError


CONF = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
PROG = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"


def _webhook_payload(sig: str = "whsig001", *, success: bool = True) -> dict:
    return {
        "signature": sig,
        "slot": 300_000_100,
        "timestamp": int(CONF.timestamp()),
        "fee": 5000,
        "transactionError": None if success else "InstructionError",
        "accountKeys": ["agentA", "cp1"],
        "accountData": [
            {"account": "agentA", "preBalance": 1_000_000_000,
             "postBalance": 999_500_000},
            {"account": "cp1", "preBalance": 2_000_000_000,
             "postBalance": 2_000_500_000},
        ],
        "programIds": [PROG],
        "computeUnitsConsumed": 200_000,
        "priorityFee": 1000,
    }


# =============================================================================
# Webhook payload decode
# =============================================================================

class TestWebhookDecode:

    def test_decode_basic_payload(self):
        update = decode_webhook_payload(_webhook_payload())
        assert update.signature == "whsig001"
        assert update.slot == 300_000_100
        assert update.is_successful is True

    def test_decode_maps_to_geyser_update_shape(self):
        # The whole point — webhook payloads decode to the SAME type the
        # Geyser path uses, so they feed the same writer.
        update = decode_webhook_payload(_webhook_payload())
        assert update.account_keys == ("agentA", "cp1")
        assert len(update.account_changes) == 2
        assert update.instr_program_ids == (PROG,)
        assert update.priority_fee_lamports == 1000

    def test_failed_transaction(self):
        update = decode_webhook_payload(_webhook_payload(success=False))
        assert update.is_successful is False

    def test_received_at_stamped(self):
        stamp = datetime(2026, 5, 1, 12, 0, 1, tzinfo=timezone.utc)
        update = decode_webhook_payload(_webhook_payload(), received_at=stamp)
        assert update.received_at == stamp

    def test_malformed_payload_raises(self):
        with pytest.raises(WebhookDecodeError):
            decode_webhook_payload({"signature": "x"})   # missing fields

    def test_block_time_from_unix_timestamp(self):
        update = decode_webhook_payload(_webhook_payload())
        assert update.block_time == CONF


# =============================================================================
# WebhookReceiver
# =============================================================================

class TestWebhookReceiver:

    def test_accept_and_drain(self):
        receiver = WebhookReceiver(clock=lambda: CONF)
        receiver.accept(_webhook_payload("s1"))
        receiver.accept(_webhook_payload("s2"))
        assert receiver.pending_count == 2
        updates = list(receiver.updates())
        assert len(updates) == 2
        # Draining empties the receiver.
        assert receiver.pending_count == 0

    def test_accept_batch(self):
        receiver = WebhookReceiver(clock=lambda: CONF)
        receiver.accept_batch([_webhook_payload("s1"), _webhook_payload("s2"),
                               _webhook_payload("s3")])
        assert receiver.pending_count == 3

    def test_malformed_payload_dropped_not_raised(self):
        # The webhook path is best-effort — a bad payload is dropped, not
        # fatal (the Geyser path is authoritative).
        receiver = WebhookReceiver(clock=lambda: CONF)
        receiver.accept({"bad": "payload"})
        assert receiver.pending_count == 0       # dropped, no exception

    def test_is_a_stream_source(self):
        # WebhookReceiver satisfies the StreamSource interface, so the
        # indexer runner can consume it identically to the Geyser stream.
        from indexer.stream import StreamSource
        receiver = WebhookReceiver(clock=lambda: CONF)
        assert isinstance(receiver, StreamSource)


# =============================================================================
# Reconciler
# =============================================================================

class TestReconciler:

    def test_streams_agree_no_divergence(self):
        result = reconcile_agent(
            "agentA",
            geyser_signatures=["s1", "s2", "s3"],
            webhook_signatures=["s1", "s2", "s3"],
        )
        assert not result.diverged
        assert result.severity is DivergenceSeverity.NONE

    def test_geyser_missed_transactions_is_serious(self):
        # Geyser is the primary path — missing transactions is MEDIUM+.
        result = reconcile_agent(
            "agentA",
            geyser_signatures=["s1", "s2"],
            webhook_signatures=["s1", "s2", "s3", "s4"],
        )
        assert result.diverged
        assert result.severity >= DivergenceSeverity.MEDIUM
        assert result.webhook_only == ("s3", "s4")     # Geyser missed these

    def test_high_geyser_miss_rate_escalates(self):
        # Geyser missed half — escalates to HIGH.
        result = reconcile_agent(
            "agentA",
            geyser_signatures=["s1"],
            webhook_signatures=["s1", "s2", "s3"],
        )
        assert result.severity is DivergenceSeverity.HIGH
        assert result.geyser_miss_rate > 0.05

    def test_webhook_missed_transactions_is_low(self):
        # The webhook path missing transactions is expected — webhooks are
        # lossy by design — so it is only LOW severity.
        result = reconcile_agent(
            "agentA",
            geyser_signatures=["s1", "s2", "s3", "s4"],
            webhook_signatures=["s1", "s2"],
        )
        assert result.severity is DivergenceSeverity.LOW
        assert result.geyser_only == ("s3", "s4")

    def test_reconcile_all(self):
        report = reconcile_all({
            "agentA": (["s1", "s2"], ["s1", "s2"]),          # agree
            "agentB": (["s1"], ["s1", "s2", "s3"]),          # Geyser missed
            "agentC": (["s1", "s2", "s3"], ["s1"]),          # webhook missed
        })
        assert len(report.results) == 3
        assert report.any_geyser_loss               # agentB
        assert report.max_severity is DivergenceSeverity.HIGH

    def test_reconcile_all_clean(self):
        report = reconcile_all({
            "agentA": (["s1", "s2"], ["s1", "s2"]),
            "agentB": (["s3", "s4"], ["s3", "s4"]),
        })
        assert not report.any_geyser_loss
        assert report.max_severity is DivergenceSeverity.NONE
        assert report.diverged_agents == ()

    def test_reconcile_is_deterministic(self):
        args = ("agentA", ["s1", "s2"], ["s1", "s2", "s3", "s4"])
        first = reconcile_agent(*args)
        for _ in range(10):
            assert reconcile_agent(*args) == first


# =============================================================================
# Webhook fallback integration — both paths feed the same writer
# =============================================================================

class TestWebhookFallbackIntegration:

    def test_webhook_path_feeds_the_writer(self):
        # The webhook receiver, consumed through the indexer runner, writes
        # to TimescaleDB exactly like the Geyser path.
        from db import InMemoryTransactionRepo
        from indexer import GeyserIndexer, IngestionWriter, WalletFilter
        from indexer.types import IngestionSource

        receiver = WebhookReceiver(clock=lambda: CONF)
        receiver.accept(_webhook_payload("whtx1"))
        receiver.accept(_webhook_payload("whtx2"))

        wf = WalletFilter(["agentA"])
        repo = InMemoryTransactionRepo()
        writer = IngestionWriter(wf, repo)
        indexer = GeyserIndexer(receiver, writer)
        report = indexer.run(source_kind=IngestionSource.WEBHOOK)

        assert report.transactions_written == 2
        assert repo.transaction_count("agentA") == 2
        for ingested in report.ingested:
            assert ingested.source is IngestionSource.WEBHOOK
