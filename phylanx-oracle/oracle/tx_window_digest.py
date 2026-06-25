"""
oracle/tx_window_digest.py — TA-5: canonical digest of the indexed
transaction window.

THE TRUST ASSUMPTION (audit)
-----------------------------
    "TimescaleDB data is unmodified — no cryptographic commitment to
    stored data."

The on-chain certificate currently binds:
  - the SCORE (via the threshold signature),
  - the BASELINE PAYLOAD HASH (AW-03 baseline_commit_nonce + BaselineDataAccount),
  - the SCORING KERNEL HASH (AW-04 scoring_code_hash + score_components_hash).

What it does NOT bind is the IDENTIFIED SET OF TRANSACTIONS that fed the
scorer. If TimescaleDB is later mutated (DBA mistake, intrusion, replica
divergence), the score on chain can no longer be reproduced — and there
is no on-chain marker saying which rows the original score depended on.

THE MITIGATION (this file)
--------------------------
`compute_tx_window_digest(transactions, window)` returns a 32-byte SHA-256
over a CANONICAL, ORDER-INDEPENDENT serialisation of:

  - The extraction window (start, end, as integer ns-since-epoch),
  - Every Transaction in the window, in (slot, signature) lexicographic
    order, with every field included.

Any honest indexer with the same TimescaleDB rows MUST compute the same
digest. The digest is folded into the score_components_hash that's
already on chain via AW-04 — so a stored-row mutation that survives until
re-verification produces a mismatch the consumer's SDK detects.

DETERMINISM
-----------
Pure stdlib. No floats, no clock, no randomness. Two nodes given the same
transactions + window produce byte-identical digests.

INTERACTION WITH AW-03 / AW-04
------------------------------
This sits ADJACENT to existing provenance, not as a replacement:
  - AW-03 binds the BASELINE (slow-moving statistical profile).
  - AW-04 binds the SCORING KERNEL (algorithmic provenance).
  - TA-5 binds the INPUT TRANSACTIONS (raw-data provenance) —
    the missing leg of the triangle.

Each is verifiable independently by re-deriving from a fetched on-chain
account or a fetched indexer view.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from features.types import ExtractionWindow, Transaction


#: The "no transactions in this window" sentinel — distinct from a
#: byte-zero hash so an empty window is distinguishable from a missing
#: digest.
EMPTY_DIGEST: bytes = hashlib.sha256(b"phylanx.ta5.empty.window").digest()


# =============================================================================
# Canonical serialisation — pure
# =============================================================================

def _canonical_tx_bytes(tx: Transaction) -> bytes:
    """
    Canonical, fixed-layout bytes for a single Transaction. Field ordering
    is FROZEN — a change here is a TA-5 schema bump that consumers must
    notice (the digest will diverge from prior epochs).

    Layout (length-prefixed for variable-length fields, fixed-width for
    integers; little-endian throughout):

        len(signature) || signature.utf8
        slot                                    (u64 LE)
        block_time_ns                           (i64 LE, ns since epoch)
        success                                 (u8)
        len(program_ids)                        (u16 LE)
        for each program_id:
            len(pid) || pid.utf8
        sol_change                              (i64 LE)
        fee                                     (u64 LE)
        priority_fee                            (u64 LE)
        compute_units                           (u64 LE)
        len(counterparty)                       (u16 LE, 0 if None)
        counterparty.utf8                       (omitted if None)
    """
    h = hashlib.sha256()

    sig = tx.signature.encode("utf-8")
    h.update(len(sig).to_bytes(2, "little"))
    h.update(sig)

    h.update(tx.slot.to_bytes(8, "little", signed=False))

    # block_time → nanoseconds since UNIX epoch. `block_time` is always
    # tz-aware UTC by Transaction.__post_init__, so timestamp() is safe.
    ns = int(tx.block_time.timestamp() * 1_000_000_000)
    h.update(ns.to_bytes(8, "little", signed=True))

    h.update(b"\x01" if tx.success else b"\x00")

    h.update(len(tx.program_ids).to_bytes(2, "little"))
    for pid in tx.program_ids:
        encoded = pid.encode("utf-8")
        h.update(len(encoded).to_bytes(2, "little"))
        h.update(encoded)

    h.update(tx.sol_change.to_bytes(8, "little", signed=True))
    h.update(tx.fee.to_bytes(8, "little", signed=False))
    h.update(tx.priority_fee.to_bytes(8, "little", signed=False))
    h.update(tx.compute_units.to_bytes(8, "little", signed=False))

    if tx.counterparty is None:
        h.update((0).to_bytes(2, "little"))
    else:
        cp = tx.counterparty.encode("utf-8")
        h.update(len(cp).to_bytes(2, "little"))
        h.update(cp)

    return h.digest()


def _canonical_window_bytes(window: ExtractionWindow) -> bytes:
    """Canonical bytes for the window: (start_ns, end_ns) i64 little-endian."""
    h = hashlib.sha256()
    h.update(b"ta5.window.v1")
    h.update(b"\x00")
    h.update(int(window.start.timestamp() * 1_000_000_000).to_bytes(8, "little", signed=True))
    h.update(int(window.end.timestamp() * 1_000_000_000).to_bytes(8, "little", signed=True))
    return h.digest()


# =============================================================================
# compute_tx_window_digest — the public entry point
# =============================================================================

def compute_tx_window_digest(
    transactions: Sequence[Transaction],
    window: ExtractionWindow,
) -> bytes:
    """
    Return the canonical TA-5 digest for an indexed transaction window.

    The result is 32 bytes (sha256). It is ORDER-INDEPENDENT in the input
    sequence — transactions are sorted by (slot, signature) before
    hashing — so two indexers that retrieved the same rows but in a
    different query order produce identical digests.

    Empty `transactions` is legal and returns a distinct EMPTY_DIGEST
    sentinel (NOT the zero hash) so consumers can distinguish "indexer
    saw no activity" from "indexer never wrote this digest".

    Raises ValueError on duplicate signatures (TimescaleDB enforces
    PRIMARY KEY (signature) at the schema level; the digest is meaningful
    only over a deduplicated set).
    """
    if not transactions:
        # Still bind the window so empty digests for different windows
        # differ — an attacker can't substitute an empty window from
        # epoch A for an empty window in epoch B.
        h = hashlib.sha256()
        h.update(EMPTY_DIGEST)
        h.update(_canonical_window_bytes(window))
        return h.digest()

    # Deduplication contract: if signatures repeat, the caller's data is
    # bad (TimescaleDB PRIMARY KEY rules this out by design). Fail loud
    # rather than silently de-duplicate, so the bug is visible.
    sigs_seen: set[str] = set()
    for tx in transactions:
        if tx.signature in sigs_seen:
            raise ValueError(
                f"TA-5: duplicate signature {tx.signature[:16]!r}... in "
                f"input — TimescaleDB enforces uniqueness; a duplicate "
                f"here is a caller bug, not data the digest is meant to "
                f"absorb."
            )
        sigs_seen.add(tx.signature)

    # Sort by (slot, signature) — both are part of the canonical bytes,
    # so ties in slot still resolve deterministically.
    sorted_txs = sorted(transactions, key=lambda t: (t.slot, t.signature))

    # Fold per-tx digests into the running hash. Per-tx digest is itself
    # canonical, so the outer hash sees a flat stream of fixed-length
    # 32-byte chunks plus the window anchor.
    h = hashlib.sha256()
    h.update(b"ta5.tx_window.v1")
    h.update(b"\x00")
    h.update(len(sorted_txs).to_bytes(8, "little", signed=False))
    h.update(_canonical_window_bytes(window))
    for tx in sorted_txs:
        h.update(_canonical_tx_bytes(tx))
    return h.digest()


__all__ = [
    "EMPTY_DIGEST",
    "compute_tx_window_digest",
]
