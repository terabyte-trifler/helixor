"""
indexer/consensus.py — VULN-11 mitigation #3: multi-endpoint consensus.

THE PRINCIPLE
-------------
The signed-envelope verifier (`indexer/auth.py`) gates by source identity;
the RPC cross-verifier (`indexer/cross_verify.py`) probes an independent
channel. This module adds the third leg: subscribe to N independent
Geyser endpoints in parallel and only emit a transaction once at least K
of them have reported byte-identical canonical payloads.

WHY K-OF-N AT THE STREAM LEVEL
------------------------------
An attacker who compromises ONE endpoint can sign forged updates that
pass envelope verification (the signature is valid for THAT endpoint's
key). They cannot compromise K independent endpoints simultaneously
without the protocol noticing — the divergence in canonical bytes is
the signal.

CANONICAL-BYTES EQUALITY, NOT SIGNATURE EQUALITY
------------------------------------------------
Each endpoint produces its OWN signature over its OWN copy of the
canonical bytes. Consensus is on the BYTES (what the validator's chain
state says), not the signatures. Two endpoints can agree on the
transaction while signing it with different keys.

WINDOWING
---------
A `signature` may arrive on the K endpoints at slightly different times.
We hold a sliding window of partial-quorum entries; when the window for
a signature ages out before reaching quorum, it is dropped and counted
as a `dropped_no_quorum` (a low-grade alert in deployment — a sustained
non-zero rate means endpoints disagree systematically).

CONFLICT
--------
Two endpoints reporting the SAME signature with DIFFERENT canonical
bytes is a `ConflictReport` — the smoking gun. Both observations are
discarded; the alert is HIGH severity.

This module is sync; the producer reads each source's `signed_updates()`
in interleaved fashion. In deployment, the runner spawns one thread per
endpoint and pushes into a shared queue — that wiring is the deployment
seam. The CORE (windowing + quorum + conflict detection) is pure and
tested here.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from indexer.auth import (
    GeyserAuthError,
    SignedGeyserUpdate,
    TrustedGeyserSourceSet,
    canonical_update_bytes,
    verify_signed_update,
)
from indexer.types import GeyserTransactionUpdate

logger = logging.getLogger("helixor.indexer.consensus")


# =============================================================================
# Reports
# =============================================================================

@dataclass(frozen=True, slots=True)
class ConflictReport:
    """
    Two trusted sources reported the same signature with different
    canonical bytes. The HIGH-severity alert.

    `agreeing_sources` is the set of pubkeys that produced the original
    bytes; `dissenting_source` produced the divergent bytes.
    """
    signature:           str
    agreeing_sources:    tuple[bytes, ...]
    dissenting_source:   bytes


@dataclass(slots=True)
class _PartialQuorum:
    """In-flight observations for a single signature awaiting quorum."""
    canonical:        bytes
    sources:          set[bytes] = field(default_factory=set)
    first_update:     GeyserTransactionUpdate | None = None


# =============================================================================
# ConsensusStream — the K-of-N gate
# =============================================================================

class ConsensusStream:
    """
    Consume a stream of `(SignedGeyserUpdate, source_index)` tuples
    interleaved from N endpoints, and yield `GeyserTransactionUpdate`s
    that have reached `min_agreements`-of-N consensus.

    `min_agreements` must satisfy `2 <= min_agreements <= len(sources)`.
    `window_size` is the maximum number of in-flight signatures we hold
    awaiting quorum; older entries are evicted in insertion order.

    Each input must already pass envelope verification — the consensus
    stream re-verifies (cheap recomputation, defence-in-depth) so an
    upstream bypass cannot smuggle an unsigned update through.

    Returns sources rejected by envelope verification via
    `envelope_rejected_count`. Returns conflict reports via
    `drain_conflicts()` for the deployment alerter.
    """

    # TA-2: duck-typed marker that production_config.assert_source_verified_
    # for_cluster() reads to confirm the runner is consuming the verified
    # consensus path. Any class with this attr set to literal True qualifies;
    # bypass-attempts via raw YellowstoneStreamSource / ListStreamSource do
    # not have it, so the mainnet pre-flight rejects them.
    is_verified_consensus_source: bool = True

    __slots__ = (
        "_trusted", "_min_agreements", "_window_size",
        "_window",
        "_emitted", "_envelope_rejected", "_dropped_no_quorum",
        "_conflicts",
    )

    def __init__(
        self,
        trusted:         TrustedGeyserSourceSet,
        min_agreements:  int,
        *,
        total_sources:   int,
        window_size:     int = 4096,
    ) -> None:
        if min_agreements < 2:
            raise ValueError(
                f"min_agreements must be >= 2 (consensus requires at least "
                f"two independent sources), got {min_agreements}"
            )
        if min_agreements > total_sources:
            raise ValueError(
                f"min_agreements ({min_agreements}) cannot exceed "
                f"total_sources ({total_sources})"
            )
        if window_size < min_agreements:
            raise ValueError(
                f"window_size ({window_size}) must be >= min_agreements "
                f"({min_agreements})"
            )
        self._trusted = trusted
        self._min_agreements = min_agreements
        self._window_size = window_size
        # OrderedDict keyed by signature; preserves insertion order for
        # FIFO eviction when the window is full.
        self._window: "OrderedDict[str, _PartialQuorum]" = OrderedDict()
        self._emitted = 0
        self._envelope_rejected = 0
        self._dropped_no_quorum = 0
        self._conflicts: list[ConflictReport] = []

    # ── Metrics ─────────────────────────────────────────────────────────────

    @property
    def emitted_count(self) -> int:
        return self._emitted

    @property
    def envelope_rejected_count(self) -> int:
        return self._envelope_rejected

    @property
    def dropped_no_quorum_count(self) -> int:
        return self._dropped_no_quorum

    @property
    def in_flight_count(self) -> int:
        return len(self._window)

    def drain_conflicts(self) -> list[ConflictReport]:
        """Pop and return all accumulated conflict reports."""
        out = list(self._conflicts)
        self._conflicts.clear()
        return out

    # ── Core ────────────────────────────────────────────────────────────────

    def feed(
        self,
        signed_inputs: Iterable[SignedGeyserUpdate],
    ) -> Iterator[GeyserTransactionUpdate]:
        """
        Consume an interleaved iterable of signed updates from N endpoints
        and yield updates that have reached quorum.

        Per input:

          1. Re-verify the envelope. If it fails, count the rejection and
             skip — never join the quorum.
          2. Compute canonical bytes.
          3. Look up the signature in the window:
             * NEW signature: insert with canonical+source.
             * EXISTING signature, same canonical: add source to the set.
               If the set size reaches `min_agreements`, emit and evict.
             * EXISTING signature, DIFFERENT canonical: conflict.
        """
        for signed in signed_inputs:
            try:
                verify_signed_update(signed, self._trusted)
            except GeyserAuthError:
                self._envelope_rejected += 1
                continue

            sig = signed.update.signature
            canonical = canonical_update_bytes(signed.update)

            entry = self._window.get(sig)
            if entry is None:
                self._insert_new(sig, canonical, signed)
                continue

            if entry.canonical != canonical:
                self._record_conflict(sig, entry, signed.source_pubkey)
                continue

            entry.sources.add(signed.source_pubkey)
            if entry.first_update is None:
                entry.first_update = signed.update
            if len(entry.sources) >= self._min_agreements:
                self._emitted += 1
                emitted_update = entry.first_update or signed.update
                del self._window[sig]
                yield emitted_update

    # ── Window management ───────────────────────────────────────────────────

    def _insert_new(
        self,
        signature: str,
        canonical: bytes,
        signed:    SignedGeyserUpdate,
    ) -> None:
        if len(self._window) >= self._window_size:
            # FIFO eviction — oldest in-flight signature drops out.
            _, _ = self._window.popitem(last=False)
            self._dropped_no_quorum += 1
        self._window[signature] = _PartialQuorum(
            canonical=canonical,
            sources={signed.source_pubkey},
            first_update=signed.update,
        )

    def _record_conflict(
        self,
        signature: str,
        entry:     _PartialQuorum,
        source:    bytes,
    ) -> None:
        report = ConflictReport(
            signature=signature,
            agreeing_sources=tuple(sorted(entry.sources)),
            dissenting_source=source,
        )
        self._conflicts.append(report)
        logger.error(
            "consensus conflict on signature %s: %d sources agree, "
            "1 dissents (%s)",
            signature[:16], len(entry.sources),
            self._trusted.name_of(source),
        )
        # Drop the entry — neither side is trustworthy now.
        del self._window[signature]


__all__ = [
    "ConflictReport", "ConsensusStream",
]
