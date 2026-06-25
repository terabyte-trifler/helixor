"""
indexer/webhook_fallback.py — the Helius webhook fallback / reconciliation source.

The MVP ingested via Helius webhooks. Day 16 makes Geyser the primary path
— but the webhook receiver is KEPT RUNNING, for two reasons:

  1. FALLBACK — if the Geyser gRPC stream drops, the webhook path keeps
     transactions flowing into TimescaleDB (lossier and rate-limited, but
     better than a gap).
  2. RECONCILIATION — running both paths gives the reconciler (indexer/
     reconciler.py) two independent observations of the same on-chain
     truth. Divergence between them is a signal that one path is dropping
     data.

This module decodes a Helius webhook payload into the same
`GeyserTransactionUpdate` shape the Geyser path uses, so BOTH paths feed
the identical `IngestionWriter`. The writer tags each with its
`IngestionSource`, and the idempotent repository insert means a
transaction seen by both paths is stored once.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import datetime, timezone

from indexer.types import (
    GeyserAccountChange,
    GeyserTransactionUpdate,
)

logger = logging.getLogger("phylanx.indexer.webhook")


class WebhookDecodeError(Exception):
    """Raised when a Helius webhook payload cannot be parsed."""


# =============================================================================
# Helius webhook payload -> GeyserTransactionUpdate
# =============================================================================

def decode_webhook_payload(
    payload: dict,
    *,
    received_at: datetime | None = None,
) -> GeyserTransactionUpdate:
    """
    Decode one Helius enhanced-webhook transaction object into a
    `GeyserTransactionUpdate`.

    Helius webhook transactions carry the same underlying data as a Geyser
    update — signature, slot, timestamp, fee, account balance changes,
    instructions — just in a different JSON shape. Mapping it onto the
    common `GeyserTransactionUpdate` means the webhook path reuses the
    entire decode + write pipeline.

    `received_at` is stamped by the HTTP receiver the instant the webhook
    arrives — the webhook path's latency clock.

    Pure given the payload + received_at. Raises WebhookDecodeError on a
    malformed payload.
    """
    try:
        signature = payload["signature"]
        slot = int(payload["slot"])
        # Helius gives `timestamp` as unix seconds.
        block_time = datetime.fromtimestamp(
            int(payload["timestamp"]), tz=timezone.utc,
        )
        fee = int(payload.get("fee", 0))
        # `transactionError` present and non-null => the tx failed.
        is_successful = payload.get("transactionError") in (None, "", {})

        account_keys = tuple(payload.get("accountKeys", ()))

        changes = tuple(
            GeyserAccountChange(
                pubkey=c["account"],
                pre_lamports=int(c["preBalance"]),
                post_lamports=int(c["postBalance"]),
            )
            for c in payload.get("accountData", ())
            if "account" in c
            and "preBalance" in c and "postBalance" in c
        )

        program_ids = tuple(payload.get("programIds", ()))
        compute_units = int(payload.get("computeUnitsConsumed", 0))
        priority_fee = int(payload.get("priorityFee", 0))
    except (KeyError, TypeError, ValueError) as exc:
        raise WebhookDecodeError(
            f"malformed Helius webhook payload: {exc}"
        ) from exc

    # accountData may not include every key; fall back to its pubkeys if
    # accountKeys was absent.
    if not account_keys and changes:
        account_keys = tuple(c.pubkey for c in changes)

    return GeyserTransactionUpdate(
        signature=signature,
        slot=slot,
        block_time=block_time,
        is_successful=is_successful,
        fee_lamports=fee,
        compute_units=compute_units,
        account_keys=account_keys,
        account_changes=changes,
        instr_program_ids=program_ids,
        received_at=received_at,
        priority_fee_lamports=priority_fee,
    )


# =============================================================================
# WebhookReceiver — the fallback ingestion source
# =============================================================================

class WebhookReceiver:
    """
    A `StreamSource` over received Helius webhook payloads.

    A real HTTP endpoint accumulates webhook POSTs into this receiver
    (`accept`); the indexer consumes it through the same `StreamSource`
    interface as the Geyser path. Decoupling the HTTP layer from the
    decode/stream logic keeps this fully testable without a web server.
    """

    __slots__ = ("_pending", "_clock")

    def __init__(self, clock=None) -> None:
        self._pending: list[GeyserTransactionUpdate] = []
        # Injectable clock for the received_at stamp — deterministic tests.
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def accept(self, payload: dict) -> None:
        """
        Accept one Helius webhook transaction payload. Stamps `received_at`
        and decodes it; a malformed payload is logged and dropped (the
        webhook path is best-effort — the Geyser path is authoritative).
        """
        try:
            update = decode_webhook_payload(payload, received_at=self._clock())
        except WebhookDecodeError as exc:
            logger.error("dropping malformed webhook payload: %s", exc)
            return
        self._pending.append(update)

    def accept_batch(self, payloads: list[dict]) -> None:
        """A Helius webhook POST carries an array of transactions."""
        for payload in payloads:
            self.accept(payload)

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    # ── StreamSource interface ──────────────────────────────────────────────

    def updates(self) -> Iterator[GeyserTransactionUpdate]:
        """Yield (and drain) the accumulated webhook updates."""
        pending, self._pending = self._pending, []
        yield from pending
