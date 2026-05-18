"""
indexer/stream.py — the Geyser stream source abstraction + wallet filter.

The indexer consumes a stream of `GeyserTransactionUpdate`s. Where that
stream comes from — a live Yellowstone gRPC subscription, or a synthetic
test stream — is behind the `StreamSource` interface. The indexer core
(indexer/runner.py) never knows which.

This keeps the gRPC wire details at one edge (indexer/yellowstone.py) and
makes the entire ingestion pipeline testable without a network.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Protocol, runtime_checkable

from indexer.types import GeyserTransactionUpdate


# =============================================================================
# StreamSource — the Geyser stream interface
# =============================================================================

@runtime_checkable
class StreamSource(Protocol):
    """
    A source of Geyser transaction updates.

    `updates()` yields `GeyserTransactionUpdate`s as they arrive. For a live
    gRPC source this blocks on the network; for a synthetic source it
    iterates a fixed list. The indexer treats both identically.
    """

    def updates(self) -> Iterator[GeyserTransactionUpdate]:
        ...


# =============================================================================
# WalletFilter — keep only transactions touching a registered agent
# =============================================================================

class WalletFilter:
    """
    Filters a Geyser stream down to transactions that touch a REGISTERED
    agent wallet.

    A Geyser subscription can be account-filtered server-side, but the
    indexer also filters client-side: it is the authoritative check
    ("is this account a registered Helixor agent?") and it resolves WHICH
    agent a multi-agent transaction belongs to.

    The registered-wallet set is mutable — agents register and deregister
    while the indexer runs.
    """

    __slots__ = ("_wallets",)

    def __init__(self, registered_wallets: Iterable[str] = ()) -> None:
        self._wallets: set[str] = set(registered_wallets)

    # ── Registration management ─────────────────────────────────────────────

    def register(self, wallet: str) -> None:
        self._wallets.add(wallet)

    def deregister(self, wallet: str) -> None:
        self._wallets.discard(wallet)

    @property
    def registered_count(self) -> int:
        return len(self._wallets)

    def is_registered(self, wallet: str) -> bool:
        return wallet in self._wallets

    # ── Filtering ───────────────────────────────────────────────────────────

    def matching_agents(self, update: GeyserTransactionUpdate) -> list[str]:
        """
        Every registered agent wallet this transaction touches.

        A transaction CAN touch more than one registered agent (agent A
        paying agent B). The indexer records it once per agent — each agent's
        history must be complete from its own perspective.

        Returned sorted, so downstream processing is deterministic.
        """
        return sorted(w for w in update.account_keys if w in self._wallets)

    def is_relevant(self, update: GeyserTransactionUpdate) -> bool:
        """True iff the transaction touches at least one registered agent."""
        return any(w in self._wallets for w in update.account_keys)


# =============================================================================
# ListStreamSource — a synthetic StreamSource for tests / replay
# =============================================================================

class ListStreamSource:
    """
    A `StreamSource` backed by a fixed list of updates. Used by tests and
    by deterministic replay. Yields the updates in the order given.
    """

    __slots__ = ("_updates",)

    def __init__(self, updates: Iterable[GeyserTransactionUpdate]) -> None:
        self._updates = list(updates)

    def updates(self) -> Iterator[GeyserTransactionUpdate]:
        yield from self._updates
