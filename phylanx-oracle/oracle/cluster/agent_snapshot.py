"""
oracle/cluster/agent_snapshot.py — VULN-15 MITIGATION: epoch agent-set snapshot.

THE AUDIT FINDING (paraphrased)
-------------------------------
MEDIUM. The commit-reveal protocol (`commit_reveal.py`) sorts agents in
`canonical_scores()` for determinism, but the SET OF AGENTS is not pinned
across the protocol's two phases. An attacker who rapidly registers or
deregisters agents BETWEEN a node's commit and reveal can force the
canonical byte sequence to differ between when the commit was hashed
and when honest verifiers recompute the hash — making honest nodes'
reveals fail verification, even though their scores are correct. Worst
case: an attacker can grief consensus into producing no result for an
epoch by repeatedly registering an agent right before commit and
deregistering it right before reveal.

THE PROTOCOL (this file)
------------------------
An `EpochAgentSnapshot` is an IMMUTABLE, hash-pinned record of "the
exact set of agents in scope for THIS epoch". It is computed ONCE at
the start of every epoch from the agent set the cluster runner sees at
that moment, and every node binds to it for the entire commit-reveal
round. The snapshot's `snapshot_hash` is folded into `compute_commit_hash`
so the commit binds to BOTH (the scores AND the agent set those scores
were computed against). At reveal time, the same snapshot_hash is folded
in — if the set has drifted, verification fails and the divergence is
caught LOCALLY, not after the cluster wasted a round.

WHY A SEPARATE HASH (not just the agent list inside canonical(scores))
----------------------------------------------------------------------
The audit-relevant invariant is "every honest node was working from the
same agent SET". A score's canonical encoding includes the agent wallet,
yes — but only for agents the node actually scored. If two nodes
disagree on the SET (one saw 5 agents, another saw 4 because one was
deregistered mid-epoch), the scored agents per node differ, so their
canonical(scores) differ NATURALLY — but the failure mode looks like
"different scores" instead of "different sets". A separate
snapshot_hash names the divergence cleanly: a reveal that fails ONLY
because the snapshot_hashes diverged is a "set drift" failure, not a
"scores diverged" failure. The watchdog distinguishes the two; the
audit response is different.

CANONICAL ENCODING
------------------
The hash is over a CANONICAL byte string so two nodes computing it
independently produce a byte-identical hash:

    bytes = "HXR-EPOCH-SNAPSHOT\0" || epoch_id (u64 BE)
         || agent_count (u32 BE)
         || for each wallet in sorted(wallets):
                wallet_len (u16 BE) || wallet (utf-8)

The "HXR-EPOCH-SNAPSHOT" domain-separation prefix prevents a snapshot
hash from being accidentally interchanged with any other sha256 hash
on the protocol surface (commit hashes, baseline hashes, cert hashes).
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable
from dataclasses import dataclass, field


# Domain-separation prefix — pinned so a snapshot hash is never mistaken
# for any other sha256 on the protocol surface (commit hashes, baseline
# hashes, cert hashes). NUL-terminated to avoid ambiguity with a wallet
# that starts with "HXR-EPOCH-SNAPSHOT".
SNAPSHOT_DOMAIN_PREFIX = b"HXR-EPOCH-SNAPSHOT\x00"

# Snapshot hash width: sha256.
SNAPSHOT_HASH_BYTES = 32


class SnapshotMismatch(Exception):
    """
    Raised when two `EpochAgentSnapshot`s that should describe the same
    epoch carry different hashes — i.e. the cluster's view of the agent
    set has drifted between two checkpoints. Surfaces the audit's
    "honest nodes committed to {A,B,C} but C deregistered before reveal"
    case as a typed failure with both hashes attached for postmortem.
    """

    def __init__(
        self,
        epoch_id:    int,
        expected:    bytes,
        actual:      bytes,
        context:     str = "",
    ) -> None:
        self.epoch_id = epoch_id
        self.expected = expected
        self.actual = actual
        self.context = context
        super().__init__(
            f"VULN-15: epoch {epoch_id} agent-set snapshot mismatch — "
            f"expected {expected.hex()[:16]}…, got {actual.hex()[:16]}…"
            + (f" ({context})" if context else "")
        )


# =============================================================================
# Pure canonical encoder + hasher
# =============================================================================

def canonical_snapshot_bytes(epoch_id: int, wallets: Iterable[str]) -> bytes:
    """
    Encode (epoch_id, agent set) to its CANONICAL byte string — the
    exact bytes every node must reach independently for `snapshot_hash`
    to match.

    Wallets are sorted, de-duplicated, then length-prefixed individually
    and as a list. The epoch id is included so two different epochs with
    the same agent set never collide.

    Pure + deterministic.
    """
    if epoch_id < 0:
        raise ValueError(f"epoch_id must be non-negative, got {epoch_id}")
    sorted_unique = sorted({w for w in wallets})        # de-dup + sort
    parts: list[bytes] = [SNAPSHOT_DOMAIN_PREFIX]
    parts.append(epoch_id.to_bytes(8, "big"))
    parts.append(len(sorted_unique).to_bytes(4, "big"))
    for wallet in sorted_unique:
        encoded = wallet.encode("utf-8")
        parts.append(len(encoded).to_bytes(2, "big"))
        parts.append(encoded)
    return b"".join(parts)


def compute_snapshot_hash(epoch_id: int, wallets: Iterable[str]) -> bytes:
    """sha256 over the canonical encoding. Pure."""
    return hashlib.sha256(canonical_snapshot_bytes(epoch_id, wallets)).digest()


# =============================================================================
# EpochAgentSnapshot — the immutable record
# =============================================================================

@dataclass(frozen=True, slots=True)
class EpochAgentSnapshot:
    """
    The immutable, hash-pinned agent set for ONE epoch's commit-reveal
    round.

    `agent_wallets` is held as a sorted, de-duplicated tuple — the same
    order `canonical_snapshot_bytes` uses — so the in-memory shape mirrors
    the wire shape; cluster nodes can compare snapshots without re-sorting.

    `snapshot_hash` is the sha256 of the canonical encoding; it is the
    value bound into every node's commit hash for this epoch. Two nodes
    computing snapshots independently MUST produce the identical hash;
    a mismatch is a `SnapshotMismatch` raised at commit / reveal time.
    """
    epoch_id:      int
    agent_wallets: tuple[str, ...]
    snapshot_hash: bytes
    captured_at:   float = field(default=0.0)

    def __post_init__(self) -> None:
        if self.epoch_id < 0:
            raise ValueError(f"epoch_id must be non-negative, got {self.epoch_id}")
        # Re-verify the hash is consistent — caught at construction so a
        # hand-built snapshot in tests cannot smuggle a wrong hash.
        expected = compute_snapshot_hash(self.epoch_id, self.agent_wallets)
        if expected != self.snapshot_hash:
            raise ValueError(
                "snapshot_hash does not match the canonical encoding of "
                "(epoch_id, agent_wallets) — refusing to construct an "
                "internally inconsistent snapshot"
            )
        if len(self.snapshot_hash) != SNAPSHOT_HASH_BYTES:
            raise ValueError(
                f"snapshot_hash must be {SNAPSHOT_HASH_BYTES} bytes, "
                f"got {len(self.snapshot_hash)}"
            )

    @property
    def agent_count(self) -> int:
        return len(self.agent_wallets)

    def matches(self, other: "EpochAgentSnapshot") -> bool:
        """
        Two snapshots describe the same agent set IFF their hashes match
        (constant-time comparison — divergence detection must not leak
        which wallet caused the difference).
        """
        if self.epoch_id != other.epoch_id:
            return False
        return _eq_ct(self.snapshot_hash, other.snapshot_hash)

    def assert_matches(self, other: "EpochAgentSnapshot", *, context: str = "") -> None:
        """
        Like `matches`, but raises `SnapshotMismatch` on disagreement —
        the typed-failure path the cluster runner uses to surface set drift
        explicitly rather than letting it manifest as "your reveal didn't
        verify" further downstream.
        """
        if self.epoch_id != other.epoch_id:
            raise SnapshotMismatch(
                self.epoch_id, self.snapshot_hash, other.snapshot_hash,
                context=f"epoch id mismatch ({self.epoch_id} vs {other.epoch_id})"
                        + (f"; {context}" if context else ""),
            )
        if not _eq_ct(self.snapshot_hash, other.snapshot_hash):
            raise SnapshotMismatch(
                self.epoch_id, self.snapshot_hash, other.snapshot_hash,
                context=context,
            )


def _eq_ct(a: bytes, b: bytes) -> bool:
    """Constant-time bytes comparison — avoids leaking divergence timing."""
    import secrets as _secrets
    return _secrets.compare_digest(a, b)


# =============================================================================
# Factory
# =============================================================================

def compute_snapshot(
    epoch_id: int,
    wallets:  Iterable[str],
    *,
    now:      float | None = None,
) -> EpochAgentSnapshot:
    """
    Construct an `EpochAgentSnapshot` from an iterable of wallets.

    Sorts + de-duplicates the input; the captured `agent_wallets` is the
    canonical-order tuple. `now` defaults to wall-clock — pass an explicit
    value in tests for determinism.
    """
    sorted_unique = tuple(sorted({w for w in wallets}))
    snapshot_hash = compute_snapshot_hash(epoch_id, sorted_unique)
    return EpochAgentSnapshot(
        epoch_id=epoch_id,
        agent_wallets=sorted_unique,
        snapshot_hash=snapshot_hash,
        captured_at=now if now is not None else time.time(),
    )
