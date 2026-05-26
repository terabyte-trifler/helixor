"""
oracle/multi_rpc.py — TA-8: multi-RPC consensus for the oracle's Solana
RPC reads.

THE TRUST ASSUMPTION (audit)
-----------------------------
    "Solana RPC endpoint is honest — if using a third-party RPC,
    MITM possible."

The Geyser indexer's SPOF-#8 (`indexer/production_config.py`) and the
SDK's slot-anchor cross-check already remove single-RPC trust from the
INGEST and CONSUMER edges. What remained was the oracle's COMMIT path:
`oracle/commit_baseline.py` reads `SOLANA_RPC_URL` and trusts whatever
that one endpoint returns when it submits a baseline commit / score
transaction. A compromised RPC there can:

  * lie about the current slot or block hash (forge an "anchor"),
  * race the cluster's view (sign-and-replay across a fork-of-one),
  * silently drop the submission and pretend it landed.

THE MITIGATION (this file)
--------------------------
`MultiRpcConsensus` is the construction contract for the oracle's RPC
reads. Given N endpoint labels + a fetcher callable, it returns the
consensus value iff at least K (strict majority, ≥ ⌈N/2⌉ + 1 by default)
endpoints agree. Anything else raises `RpcDivergenceError`.

The fetcher is injected so the helper is fully testable without network:

    consensus = MultiRpcConsensus(endpoints=["helius", "triton", "quicknode"])
    head = await consensus.fetch(
        fetcher=lambda label: client[label].get_slot(),
    )

DETERMINISM
-----------
Pure stdlib + injected callable. No clock, no randomness — the result is
the K-of-N agreed value or a typed error. Two oracle nodes given the
same per-endpoint responses produce the same outcome.

INTERACTION WITH SPOF-#8
------------------------
SPOF-#8 mitigated the INGEST stream with `ConsensusStream`. TA-8 mitigates
RPC READS (slot, block hash, account state) with this module. The two
gate together: a process whose ingest is consensus-verified but whose
RPC reads are single-trust is still exposed to TA-8 — and vice-versa.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Generic, TypeVar


T = TypeVar("T")


#: TA-8 mainnet floor: at least three independent RPC endpoints. Two is
#: enough to detect disagreement but not enough to break ties; three is
#: the smallest configuration that can survive one compromised /
#: misconfigured endpoint and still produce a winning quorum.
MAINNET_MIN_RPC_ENDPOINTS = 3

#: Hard floor on K — the K=1 case is "trust any one endpoint" which is
#: the very SPOF this module exists to forbid.
MIN_RPC_CONSENSUS_THRESHOLD = 2


# =============================================================================
# Errors
# =============================================================================

class RpcDivergenceError(RuntimeError):
    """
    Raised when fewer than K endpoints agreed on a value, OR when one or
    more endpoints raised an exception and the remaining quorum is
    insufficient.

    The exception's `.report` carries the per-endpoint outcome map for
    operator inspection — which endpoint diverged, with what value.
    """

    def __init__(self, message: str, report: "RpcConsensusReport"):
        super().__init__(message)
        self.report = report


class MultiRpcConfigError(ValueError):
    """Raised on a malformed MultiRpcConsensus construction."""


# =============================================================================
# RpcConsensusReport — the per-endpoint outcome
# =============================================================================

@dataclass(frozen=True, slots=True)
class RpcConsensusReport(Generic[T]):
    """
    Per-endpoint outcome of a single multi-RPC fetch.

    `responses` maps endpoint label → fetched value (or None if the
    endpoint raised).
    `errors` maps endpoint label → exception repr (or None if the
    endpoint returned a value).
    `consensus_value` is the K-of-N agreed value, or None on divergence.
    """
    responses:        dict[str, T | None]
    errors:           dict[str, str | None]
    consensus_value:  T | None
    agreeing_count:   int
    threshold:        int

    @property
    def reached_consensus(self) -> bool:
        return self.consensus_value is not None


# =============================================================================
# MultiRpcConsensus — the public API
# =============================================================================

class MultiRpcConsensus(Generic[T]):
    """
    K-of-N RPC consensus for one fetch call. The fetcher is invoked once
    per endpoint; the result must be hashable (used as a dict key for
    the Counter).

    `endpoints` is the list of labels the fetcher is called with.
    `min_agreements` defaults to a strict majority (floor(N/2)+1), floor
    of `MIN_RPC_CONSENSUS_THRESHOLD`.

    For mainnet deployments, callers SHOULD pass at least
    `MAINNET_MIN_RPC_ENDPOINTS` endpoints; the constructor raises if
    `min_agreements > len(endpoints)`.
    """

    __slots__ = ("_endpoints", "_min_agreements")

    def __init__(
        self,
        *,
        endpoints:       Sequence[str],
        min_agreements:  int | None = None,
    ) -> None:
        unique = list(dict.fromkeys(endpoints))
        if len(unique) != len(endpoints):
            raise MultiRpcConfigError(
                f"endpoints contains duplicate labels: {list(endpoints)!r}",
            )
        if not endpoints:
            raise MultiRpcConfigError("endpoints must be non-empty")

        if min_agreements is None:
            min_agreements = max(
                MIN_RPC_CONSENSUS_THRESHOLD if len(endpoints) >= 2 else 1,
                (len(endpoints) // 2) + 1,
            )
        if min_agreements < 1:
            raise MultiRpcConfigError(
                f"min_agreements must be >= 1, got {min_agreements}",
            )
        if min_agreements > len(endpoints):
            raise MultiRpcConfigError(
                f"min_agreements ({min_agreements}) cannot exceed the "
                f"endpoint count ({len(endpoints)})",
            )

        self._endpoints = tuple(endpoints)
        self._min_agreements = int(min_agreements)

    @property
    def endpoints(self) -> tuple[str, ...]:
        return self._endpoints

    @property
    def min_agreements(self) -> int:
        return self._min_agreements

    def fetch(self, fetcher: Callable[[str], T]) -> RpcConsensusReport[T]:
        """
        Invoke `fetcher(label)` for every endpoint; return the consensus
        report. Raises `RpcDivergenceError` iff fewer than
        `min_agreements` endpoints returned the SAME value.

        Endpoints that raise are recorded in `report.errors` and do not
        contribute to the tally. If too few endpoints succeed to reach
        the threshold, the divergence error is raised with the full
        per-endpoint report attached.
        """
        responses: dict[str, T | None] = {}
        errors: dict[str, str | None] = {}
        for label in self._endpoints:
            try:
                value = fetcher(label)
                responses[label] = value
                errors[label] = None
            except Exception as exc:  # noqa: BLE001 — per-RPC isolation
                responses[label] = None
                errors[label] = f"{type(exc).__name__}: {exc}"

        # Count value frequencies — only over endpoints that returned.
        present_values = [v for v in responses.values() if v is not None]
        counts: Counter[T] = Counter(present_values)
        winner: T | None = None
        agreeing = 0
        if counts:
            value, count = counts.most_common(1)[0]
            if count >= self._min_agreements:
                winner = value
                agreeing = count

        report = RpcConsensusReport(
            responses=responses,
            errors=errors,
            consensus_value=winner,
            agreeing_count=agreeing,
            threshold=self._min_agreements,
        )

        if winner is None:
            raise RpcDivergenceError(
                f"TA-8: multi-RPC fetch failed to reach quorum "
                f"({self._min_agreements} of {len(self._endpoints)} required, "
                f"top tally {counts.most_common(1)[0][1] if counts else 0}). "
                f"Per-endpoint responses: {responses!r}. Errors: {errors!r}.",
                report,
            )

        return report


__all__ = [
    "MAINNET_MIN_RPC_ENDPOINTS",
    "MIN_RPC_CONSENSUS_THRESHOLD",
    "MultiRpcConfigError",
    "MultiRpcConsensus",
    "RpcConsensusReport",
    "RpcDivergenceError",
]
