"""
oracle/cluster/agent_set_buffer.py — VULN-15 MITIGATION (second half).

THE AUDIT FINDING (paraphrased)
-------------------------------
MEDIUM. Even with an epoch snapshot pinning the agent set during a
single commit-reveal round (`agent_snapshot.py`), the live registration
event stream can still cause WHICH agents are in scope to flap between
epochs in a way that is hard to reason about — and an attacker who
register/deregister-spams across an epoch boundary can still race the
runner's "compute snapshot" step. The audit asks for the COMPLEMENTARY
property: "any registrations / deregistrations take effect at the
epoch boundary, not mid-epoch."

THE PROTOCOL (this file)
------------------------
An `AgentSetBuffer` is the operator-facing seam where agent
registrations and deregistrations are received and BUFFERED. Changes do
NOT mutate the in-scope set immediately; instead they queue as
`PendingChange`s. Once per epoch, the cluster runner calls
`apply_pending(next_epoch_id)` — the buffer atomically folds all
queued changes into the next epoch's agent set, returns the resulting
frozen set, and clears its queue. The snapshot computed for that
epoch (`compute_snapshot`) sees the folded set; everything that
arrives after the apply window queues for the NEXT boundary.

This forces every node in the cluster — whose buffers are fed by the
same on-chain registration event stream and which all flush at the
same epoch boundary — to enter each epoch with the SAME agent set,
regardless of the exact moment a registration's confirmation lands.

WHY ATOMIC APPLY (not "snapshot-then-clear")
--------------------------------------------
Two reasons:

  1. The buffer's invariant is a SINGLE state transition per epoch:
     "the set went from X to Y at the boundary." If you allowed
     mid-epoch peeks at "what will the set become?", a node could
     accidentally use the peeked value somewhere and stale-bind. The
     buffer exposes only `current_set` (the active set) and
     `apply_pending` (the boundary step). No half-applied state.

  2. The audit-relevant attack is "the attacker registered, the snapshot
     captured them, then they deregistered mid-epoch." The defence is
     that the snapshot was the SOLE input to the round's hash binding;
     the buffer guarantees the snapshot saw a SET that did not
     subsequently shift inside that epoch. The buffer's atomic apply
     is the operational embodiment of that guarantee.

PENDING CHANGES
---------------
A `PendingChange` is a single (kind, wallet) tuple. `REGISTER` adds the
wallet to the next set if not present; `DEREGISTER` removes it. Multiple
queued changes on the same wallet collapse to the LAST one queued — the
buffer is a state machine, not an event log; reordering register/
deregister/register within one epoch boundary results in the wallet
being present. This matches Solana's last-write-wins semantics for the
on-chain `agent_registration` PDA.

DETERMINISM
-----------
The buffer is pure given its inputs. Application order is sorted by
wallet so two nodes processing the same queued changes always produce
the byte-identical resulting set.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass, field
from typing import Iterable


logger = logging.getLogger("helixor.oracle.cluster.agent_set_buffer")


# =============================================================================
# Pending change kinds
# =============================================================================

class PendingChangeKind(enum.Enum):
    """The kind of a buffered agent-set change."""
    REGISTER   = "register"
    DEREGISTER = "deregister"


@dataclass(frozen=True, slots=True)
class PendingChange:
    """One buffered change — either register or deregister `wallet`."""
    kind:   PendingChangeKind
    wallet: str

    def __post_init__(self) -> None:
        if not self.wallet:
            raise ValueError("wallet must be non-empty")


# =============================================================================
# Result of an atomic apply step
# =============================================================================

@dataclass(frozen=True, slots=True)
class AppliedSnapshot:
    """
    The outcome of one `apply_pending` step — the new active set and the
    diff that was folded in. Surfaced so the runner can log / emit
    `agent.registration_events` for the audit trail (downstream
    consumers care about "agent X became active at epoch N").
    """
    epoch_id:      int
    new_set:       frozenset[str]
    registered:    tuple[str, ...]    # wallets added at this boundary
    deregistered:  tuple[str, ...]    # wallets removed at this boundary

    @property
    def change_count(self) -> int:
        return len(self.registered) + len(self.deregistered)


# =============================================================================
# AgentSetBuffer
# =============================================================================

class AgentSetBuffer:
    """
    The operator-facing seam for agent registration / deregistration.

    Construction:
        initial: the in-scope agent set at construction time. Empty by
                 default (a fresh cluster has no agents yet).

    Use:
        buf.enqueue_register("agentA")     # buffered, NOT applied
        buf.enqueue_deregister("agentB")   # buffered, NOT applied
        # ... other events queue up during an epoch ...
        applied = buf.apply_pending(next_epoch_id=42)
        # `applied.new_set` is the set the next epoch's snapshot
        # captures; `buf.current_set` returns it from here on.

    Threading: not thread-safe. The cluster runner is the sole writer in
    today's deployment; if concurrency arrives, wrap the buffer in a
    lock at the runner level — keeping the buffer itself lock-free
    keeps it pure and trivially testable.
    """

    def __init__(self, initial: Iterable[str] = ()) -> None:
        # Frozen so callers cannot reach in and mutate the active set,
        # which would silently violate the "boundary-only changes"
        # invariant.
        self._current_set: frozenset[str] = frozenset(initial)
        # The pending queue is per-wallet, not append-only: a wallet can
        # only have ONE buffered terminal state at the next boundary
        # (register OR deregister), and the latest enqueue wins. This
        # mirrors the on-chain PDA's last-write-wins semantics.
        self._pending: dict[str, PendingChangeKind] = {}
        # Monotonic counter of completed apply steps — exposed for
        # operator dashboards.
        self._applied_epochs: int = 0

    # ── Read-only state ────────────────────────────────────────────────────

    @property
    def current_set(self) -> frozenset[str]:
        """The currently active agent set (the set the LAST `apply_pending` produced)."""
        return self._current_set

    @property
    def pending_count(self) -> int:
        """Number of distinct wallets with a buffered change."""
        return len(self._pending)

    @property
    def applied_epochs(self) -> int:
        return self._applied_epochs

    def has_pending(self, wallet: str) -> bool:
        return wallet in self._pending

    def pending_kind(self, wallet: str) -> PendingChangeKind | None:
        return self._pending.get(wallet)

    # ── Enqueue (does NOT mutate current_set) ──────────────────────────────

    def enqueue_register(self, wallet: str) -> None:
        """
        Queue a registration of `wallet` for the next epoch boundary. If
        the wallet is already in `current_set`, the enqueue is a no-op
        at apply time — the wallet remains present. Re-enqueuing
        overrides any prior pending change for the same wallet.
        """
        if not wallet:
            raise ValueError("wallet must be non-empty")
        self._pending[wallet] = PendingChangeKind.REGISTER

    def enqueue_deregister(self, wallet: str) -> None:
        """
        Queue a deregistration of `wallet` for the next epoch boundary.
        If the wallet is not in `current_set` and has no pending
        registration, the enqueue is a no-op at apply time. Re-enqueuing
        overrides any prior pending change for the same wallet.
        """
        if not wallet:
            raise ValueError("wallet must be non-empty")
        self._pending[wallet] = PendingChangeKind.DEREGISTER

    def enqueue(self, change: PendingChange) -> None:
        """Dispatch on a `PendingChange` — convenience for replaying events."""
        if change.kind is PendingChangeKind.REGISTER:
            self.enqueue_register(change.wallet)
        else:
            self.enqueue_deregister(change.wallet)

    # ── Atomic apply at an epoch boundary ──────────────────────────────────

    def apply_pending(self, next_epoch_id: int) -> AppliedSnapshot:
        """
        Atomically fold every queued change into `current_set` for the
        start of `next_epoch_id`. After this call:
          - `current_set` reflects the post-boundary set,
          - the pending queue is EMPTY,
          - `applied_epochs` ticks by one.

        Returns an `AppliedSnapshot` carrying the new set plus the
        wallet-level diff (for audit log emission). The diff is sorted
        so two nodes processing the same queued changes produce the
        byte-identical diff record.
        """
        if next_epoch_id < 0:
            raise ValueError(f"next_epoch_id must be non-negative, got {next_epoch_id}")

        new_set = set(self._current_set)
        added:   list[str] = []
        removed: list[str] = []

        # Sorted so the diff record is deterministic across nodes — two
        # nodes processing the same buffer must report the same
        # (registered, deregistered) tuples even though dict iteration
        # order is insertion-ordered.
        for wallet in sorted(self._pending):
            kind = self._pending[wallet]
            if kind is PendingChangeKind.REGISTER:
                if wallet not in new_set:
                    new_set.add(wallet)
                    added.append(wallet)
            else:                                  # DEREGISTER
                if wallet in new_set:
                    new_set.discard(wallet)
                    removed.append(wallet)
        applied = AppliedSnapshot(
            epoch_id=next_epoch_id,
            new_set=frozenset(new_set),
            registered=tuple(added),
            deregistered=tuple(removed),
        )

        self._current_set = applied.new_set
        self._pending.clear()
        self._applied_epochs += 1

        if applied.change_count:
            logger.info(
                "VULN-15 agent-set buffer applied at epoch %d: "
                "+%d registered, -%d deregistered, %d active",
                next_epoch_id,
                len(applied.registered),
                len(applied.deregistered),
                len(applied.new_set),
            )
        return applied

    # ── Operator-facing introspection ──────────────────────────────────────

    def pending_changes(self) -> tuple[PendingChange, ...]:
        """
        The current pending queue as a sorted tuple — for operator
        dashboards. Sorted by wallet so the dashboard never reorders
        between renders.
        """
        return tuple(
            PendingChange(kind=self._pending[w], wallet=w)
            for w in sorted(self._pending)
        )
