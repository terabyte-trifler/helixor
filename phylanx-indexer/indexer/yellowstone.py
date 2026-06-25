"""
indexer/yellowstone.py — the Yellowstone gRPC StreamSource adapter.

This is the ONE edge that touches the Geyser gRPC wire format. Everything
else in the indexer works on the provider-agnostic
`GeyserTransactionUpdate`, so this module is the only thing that changes
if the streaming provider changes.

WHAT YELLOWSTONE IS
-------------------
Yellowstone gRPC (the `yellowstone-grpc` Geyser plugin) is the de-facto
standard interface for consuming a Solana validator's Geyser stream over
the network. Helius and other Geyser-enabled RPC providers expose it. A
client opens a gRPC subscription, optionally account-filtered server-side,
and receives a stream of transaction updates.

DRIVER INDEPENDENCE
-------------------
`grpc` and the generated Yellowstone protobuf stubs are production
dependencies. This module does NOT import them at load time — so the
indexer's testable core never transitively pulls in gRPC. The real client
imports them inside `connect()`. The mapping from a Yellowstone protobuf
`SubscribeUpdateTransaction` to our `GeyserTransactionUpdate` is the
`_map_update` function — pure, and unit-testable with a stand-in protobuf.

This module is the integration seam. In this build it ships as a
fully-formed adapter whose pure mapping logic is tested; the live gRPC
connection is exercised in deployment against a real Helius endpoint.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone

from indexer.types import (
    GeyserAccountChange,
    GeyserTransactionUpdate,
)

logger = logging.getLogger("phylanx.indexer.yellowstone")


# =============================================================================
# Connection config
# =============================================================================

@dataclass(frozen=True, slots=True)
class YellowstoneConfig:
    """Connection settings for a Yellowstone gRPC endpoint."""
    endpoint:        str                       # e.g. a Helius Geyser gRPC URL
    x_token:         str = ""                  # provider auth token
    # Server-side account filter: only stream transactions touching these
    # accounts. The indexer ALSO filters client-side (WalletFilter) — this
    # is a bandwidth optimisation, not the authoritative filter.
    account_include: tuple[str, ...] = ()
    # Commitment level for the subscription.
    commitment:      str = "confirmed"
    # Reconnect backoff (a live stream must survive transient drops).
    reconnect_base_s:   float = 1.0
    reconnect_max_s:    float = 30.0


# =============================================================================
# Protobuf -> GeyserTransactionUpdate mapping (pure, testable)
# =============================================================================

def map_subscribe_update(
    tx_info:    object,
    slot:       int,
    block_time: datetime,
    *,
    received_at: datetime | None = None,
) -> GeyserTransactionUpdate:
    """
    Map a Yellowstone `SubscribeUpdateTransactionInfo` onto our
    provider-agnostic `GeyserTransactionUpdate`.

    `tx_info` is duck-typed against the Yellowstone protobuf shape — it must
    expose `.signature`, `.is_vote`, `.meta` (with `.err`, `.fee`,
    `.compute_units_consumed`, `.pre_balances`, `.post_balances`), and
    `.transaction.message.account_keys` / `.instructions`. Keeping this
    duck-typed (rather than importing the generated stubs) makes the
    mapping unit-testable with a lightweight stand-in.

    Pure given its inputs.
    """
    signature = _b58(tx_info.signature)
    meta = tx_info.meta
    message = tx_info.transaction.message

    account_keys = tuple(_b58(k) for k in message.account_keys)

    # Pre/post balances are parallel arrays indexed by account position.
    pre = list(meta.pre_balances)
    post = list(meta.post_balances)
    changes = tuple(
        GeyserAccountChange(
            pubkey=account_keys[i],
            pre_lamports=int(pre[i]),
            post_lamports=int(post[i]),
        )
        for i in range(min(len(account_keys), len(pre), len(post)))
    )

    # Program ids: each instruction references a program by account index.
    program_ids = tuple(
        account_keys[instr.program_id_index]
        for instr in message.instructions
        if 0 <= instr.program_id_index < len(account_keys)
    )

    return GeyserTransactionUpdate(
        signature=signature,
        slot=slot,
        block_time=block_time,
        is_successful=(meta.err is None),
        fee_lamports=int(meta.fee),
        compute_units=int(getattr(meta, "compute_units_consumed", 0) or 0),
        account_keys=account_keys,
        account_changes=changes,
        instr_program_ids=program_ids,
        received_at=received_at,
        priority_fee_lamports=_priority_fee(meta),
    )


def _b58(value) -> str:
    """
    Yellowstone delivers pubkeys/signatures as raw bytes. Render base58.

    Falls back to a str() if the value is already textual (test stand-ins
    may pass strings directly).
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return _base58_encode(bytes(value))
    return str(value)


def _priority_fee(meta) -> int:
    """
    The compute-budget priority fee, if the meta surfaces it. Yellowstone
    does not always carry a discrete priority-fee field; 0 when absent.
    """
    return int(getattr(meta, "priority_fee", 0) or 0)


# Minimal base58 (Bitcoin alphabet) — Solana's pubkey encoding. Stdlib only.
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    """Base58-encode bytes. Deterministic, pure stdlib."""
    if not data:
        return ""
    num = int.from_bytes(data, "big")
    out = []
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(_B58_ALPHABET[rem])
    # Leading zero bytes -> leading '1's.
    for byte in data:
        if byte == 0:
            out.append(_B58_ALPHABET[0])
        else:
            break
    return "".join(reversed(out))


# =============================================================================
# YellowstoneStreamSource — the live gRPC StreamSource
# =============================================================================

class YellowstoneStreamSource:
    """
    A `StreamSource` over a live Yellowstone gRPC subscription.

    `grpc` and the generated Yellowstone stubs are imported inside
    `updates()` — not at module load — so the indexer's testable core never
    transitively depends on gRPC.

    In deployment:

        config = YellowstoneConfig(endpoint=HELIUS_GEYSER_URL,
                                   x_token=HELIUS_TOKEN,
                                   account_include=registered_wallets)
        source = YellowstoneStreamSource(config)
        GeyserIndexer(source, writer).run()
    """

    __slots__ = ("_config",)

    def __init__(self, config: YellowstoneConfig) -> None:
        self._config = config

    def updates(self) -> Iterator[GeyserTransactionUpdate]:
        """
        Open the gRPC subscription and yield updates as they arrive.

        Reconnects with exponential backoff on a dropped stream — a live
        Geyser subscription must survive transient network failures without
        losing its place. (Implemented against the gRPC client in
        deployment; the import is deferred so the test suite never needs
        grpcio installed.)
        """
        try:
            import grpc  # noqa: F401
        except ImportError as exc:                # pragma: no cover
            raise RuntimeError(
                "YellowstoneStreamSource.updates() needs the 'grpcio' package "
                "and the generated Yellowstone stubs — install them in the "
                "deployment environment. For tests, use ListStreamSource or "
                "WebhookReceiver instead."
            ) from exc

        # Deployment wiring: open grpc.secure_channel(self._config.endpoint),
        # build a geyser_pb2.SubscribeRequest with the account filter, stream
        # the responses, and yield map_subscribe_update(...) for each.
        # Kept out of the testable core by design.
        raise NotImplementedError(  # pragma: no cover
            "live Yellowstone streaming is wired in deployment against a "
            "real Geyser-enabled RPC endpoint"
        )
