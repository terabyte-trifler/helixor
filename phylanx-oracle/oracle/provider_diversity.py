"""
oracle/provider_diversity.py — HCR-1: RPC provider diversity gate.

THE HIDDEN CENTRALIZATION RISK (audit)
--------------------------------------
    "If all oracle nodes use the same RPC provider (e.g. Helius,
    QuickNode), a single provider outage or censorship brings down
    the entire oracle cluster's ability to submit on-chain."

TA-8 (`oracle/multi_rpc.py`) already requires K-of-N agreement across
multiple RPC ENDPOINTS for one oracle node's commit path. What TA-8
does NOT enforce is PROVIDER diversity: three endpoints can all be at
`helius-rpc.com` and still pass TA-8 (because the *endpoints* are
distinct URLs). The HCR-1 audit point is exactly this: from an outage
or censorship perspective, three Helius URLs are ONE point of failure.

THE MITIGATION (this file)
--------------------------
`verify_provider_diversity(endpoints, min_distinct=2)` classifies each
endpoint URL into a coarse PROVIDER bucket (helius / triton / quicknode /
ankr / alchemy / blockdaemon / chainstack / syndica / public Solana
Labs / unknown) and refuses any configuration where the count of
distinct providers falls below the floor.

Mainnet floor: `MIN_DISTINCT_RPC_PROVIDERS = 2`. The K=2 in TA-8 means
at least two endpoints must agree for a commit to land; HCR-1 ensures
those two endpoints CANNOT both be at the same provider, so the
attacker has to coerce two independent commercial entities, not one.

Provider classification is by host-suffix match against
`KNOWN_PROVIDERS`. An unknown host is bucketed as `unknown:<host>` —
every distinct unknown host counts as its own provider. This is the
conservative default: a self-hosted validator at a private endpoint
DOES contribute to diversity, whereas two endpoints sharing the
same private hostname do NOT.

DETERMINISM
-----------
Pure stdlib (`urllib.parse`). No network, no clock, no randomness. Two
nodes with the same endpoint list produce the same report.

INTERACTION WITH TA-8
---------------------
HCR-1 is a PRECONDITION to TA-8: the oracle's commit path should
verify provider diversity BEFORE handing the endpoint list to
`MultiRpcConsensus`. A configuration that passes HCR-1 + TA-8 has
both (a) K-of-N agreement on the chain projection AND (b) the K
agreers cannot collapse into one corporate or censorable entity.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import urlparse


# =============================================================================
# Provider classification table
# =============================================================================
#
# Maps a host SUFFIX to a coarse provider ID. A host matches a suffix iff
# `host == suffix` or `host.endswith("." + suffix)`. Order does not
# matter — the table is consulted host-by-host, longest-suffix first, by
# `classify_provider()`.

KNOWN_PROVIDERS: Mapping[str, str] = {
    # Helius
    "helius-rpc.com":      "helius",
    "helius.xyz":          "helius",
    "helius.dev":          "helius",
    # Triton / Jump RPC pool
    "rpcpool.com":         "triton",
    "triton.one":          "triton",
    # QuickNode
    "quicknode.com":       "quicknode",
    "quiknode.pro":        "quicknode",
    "solana-mainnet.quiknode.pro": "quicknode",
    # Alchemy
    "alchemy.com":         "alchemy",
    "alchemyapi.io":       "alchemy",
    "g.alchemy.com":       "alchemy",
    # Ankr
    "ankr.com":            "ankr",
    "rpc.ankr.com":        "ankr",
    # Blockdaemon
    "blockdaemon.com":     "blockdaemon",
    # Chainstack
    "chainstack.com":      "chainstack",
    # Syndica
    "syndica.io":          "syndica",
    "solana-mainnet.api.syndica.io": "syndica",
    # GetBlock
    "getblock.io":         "getblock",
    # Extrnode
    "extrnode.com":        "extrnode",
    # Solana Labs public endpoints (the canonical default — high
    # availability is NOT guaranteed; cluster bucket is "solana-labs")
    "solana.com":          "solana-labs",
    "mainnet.solana.com":  "solana-labs",
    "api.mainnet-beta.solana.com": "solana-labs",
    "devnet.solana.com":   "solana-labs",
    "api.devnet.solana.com": "solana-labs",
    "testnet.solana.com":  "solana-labs",
    "api.testnet.solana.com": "solana-labs",
    # Project Serum (legacy, still routes to a single org)
    "projectserum.com":    "serum",
}


#: HCR-1 mainnet floor: at least two distinct RPC providers across the
#: endpoint list. One is degenerate (the whole point of HCR-1); two is
#: the smallest configuration where a one-provider outage still leaves
#: an honest path open to the chain.
MIN_DISTINCT_RPC_PROVIDERS = 2


#: Sentinel prefix for hosts not in the `KNOWN_PROVIDERS` table.
#: Distinct unknown hosts count as distinct providers — a self-hosted
#: validator behind a private hostname legitimately adds diversity.
_UNKNOWN_PROVIDER_PREFIX = "unknown:"


# =============================================================================
# Errors
# =============================================================================

class ProviderDiversityError(RuntimeError):
    """
    Raised when an endpoint list collapses onto fewer than
    `MIN_DISTINCT_RPC_PROVIDERS` distinct provider buckets.

    The exception's `.report` carries the per-endpoint provider
    classification so the operator can see WHICH endpoints
    over-concentrated.
    """

    def __init__(self, message: str, report: "ProviderDiversityReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# ProviderDiversityReport — the per-endpoint outcome
# =============================================================================

@dataclass(frozen=True, slots=True)
class ProviderDiversityReport:
    """
    Result of one diversity check.

    `endpoints`  the input URLs, in input order.
    `providers`  the provider bucket for each (parallel to `endpoints`).
    `distinct_count`  number of distinct provider buckets.
    `is_diverse`  True iff `distinct_count >= min_distinct` of the check.
    """
    endpoints:       tuple[str, ...]
    providers:       tuple[str, ...]
    distinct_count:  int
    min_distinct:    int

    @property
    def is_diverse(self) -> bool:
        return self.distinct_count >= self.min_distinct


# =============================================================================
# Classification
# =============================================================================

def classify_provider(url: str) -> str:
    """
    Map a URL to its coarse provider bucket.

    Match is by host-suffix against `KNOWN_PROVIDERS`. Hosts not in
    the table are bucketed as `"unknown:<host>"` so distinct unknown
    hosts count as distinct providers (a self-hosted validator at a
    private hostname legitimately adds diversity).

    Raises `ValueError` on an unparseable URL — the caller should catch
    parsing errors at config-load time, not at commit time.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError(
            f"cannot classify RPC provider — URL has no host: {url!r}"
        )

    # Longest suffix wins so that `api.mainnet-beta.solana.com` matches
    # the specific bucket, not the broader `solana.com` one.
    best_suffix = ""
    best_provider = ""
    for suffix, provider in KNOWN_PROVIDERS.items():
        suffix_lc = suffix.lower()
        matches = host == suffix_lc or host.endswith("." + suffix_lc)
        if matches and len(suffix_lc) > len(best_suffix):
            best_suffix = suffix_lc
            best_provider = provider
    if best_provider:
        return best_provider

    return f"{_UNKNOWN_PROVIDER_PREFIX}{host}"


# =============================================================================
# Diversity gate
# =============================================================================

def verify_provider_diversity(
    endpoints:     Sequence[str],
    *,
    min_distinct: int = MIN_DISTINCT_RPC_PROVIDERS,
) -> ProviderDiversityReport:
    """
    Verify that the endpoint list spans at least `min_distinct` distinct
    provider buckets. Returns the report on success; raises
    `ProviderDiversityError` (with the report attached) on failure.

    The caller is expected to invoke this BEFORE handing the endpoint
    list to `MultiRpcConsensus` — a configuration where K=2 endpoints
    agree but both sit at one provider is the HCR-1 failure mode.
    """
    if not endpoints:
        raise ProviderDiversityError(
            "HCR-1: endpoints must be non-empty",
            ProviderDiversityReport(
                endpoints=(),
                providers=(),
                distinct_count=0,
                min_distinct=min_distinct,
            ),
        )
    if min_distinct < 1:
        raise ProviderDiversityError(
            f"HCR-1: min_distinct must be >= 1, got {min_distinct}",
            ProviderDiversityReport(
                endpoints=tuple(endpoints),
                providers=(),
                distinct_count=0,
                min_distinct=min_distinct,
            ),
        )

    providers = tuple(classify_provider(e) for e in endpoints)
    distinct_count = len(set(providers))
    report = ProviderDiversityReport(
        endpoints=tuple(endpoints),
        providers=providers,
        distinct_count=distinct_count,
        min_distinct=min_distinct,
    )
    if distinct_count < min_distinct:
        raise ProviderDiversityError(
            f"HCR-1: only {distinct_count} distinct RPC provider(s) across "
            f"{len(endpoints)} endpoints (need at least {min_distinct}). "
            f"Per-endpoint providers: {dict(zip(report.endpoints, report.providers))!r}. "
            f"A single-provider outage or censorship would halt the entire "
            f"cluster's ability to submit on-chain. Configure additional "
            f"endpoints from a SECOND provider before retrying.",
            report,
        )
    return report


__all__ = [
    "KNOWN_PROVIDERS",
    "MIN_DISTINCT_RPC_PROVIDERS",
    "ProviderDiversityError",
    "ProviderDiversityReport",
    "classify_provider",
    "verify_provider_diversity",
]
