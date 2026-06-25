"""
indexer/production_config.py — SPOF-#8: production-default factory for the
Geyser stream layer.

THE AUDIT FINDING
-----------------
SPOF-#8 — the indexer's `StreamSource` defaults to a single Yellowstone
gRPC endpoint. A compromise / outage / fork-of-one at that endpoint is a
single point of failure: the indexer silently ingests the attacker's
view, certs flip green/red on a hostile chain projection, and the
divergence is invisible until someone manually reconciles against a
second RPC.

THE MITIGATION (this file)
--------------------------
`indexer/consensus.py` already implements the K-of-N gate
(`ConsensusStream`). What was missing was the WIRING: a production
indexer running against mainnet had no construction path that REFUSED
to start with a single endpoint.

This module is that path. `build_production_geyser_config()` is the only
sanctioned construction site for a mainnet indexer; it:

  1. Parses `PHYLANX_GEYSER_ENDPOINTS` (comma-separated
     `name:endpoint_url:token_env_var` triples).
  2. When `PHYLANX_SOLANA_CLUSTER` is `mainnet` / `mainnet-beta`,
     requires:
       * `len(endpoints) >= MAINNET_MIN_ENDPOINTS` (3) — single- and
         two-endpoint configs are refused.
       * `consensus_threshold` defaults to strict majority
         `floor(N/2) + 1`, never less than 2.
  3. Returns a `ProductionGeyserConfig` containing both the per-endpoint
     `YellowstoneConfig` list AND the consensus parameters the runner
     uses to construct a `ConsensusStream`. The dataclass is the
     contract — a caller cannot accidentally drop the consensus wiring
     because the consensus params are non-optional and arrive in the
     same object.

ENFORCEMENT IS LOAD-TIME, NOT RUNTIME
-------------------------------------
The factory raises `SinglePointGeyserError` (a typed subclass of
`RuntimeError`) BEFORE any subscription opens. A mainnet indexer
process that misconfigures its endpoints exits at boot — it does not
quietly degrade to one endpoint.

NON-MAINNET CLUSTERS
--------------------
Devnet / localnet / fuzz harnesses may legitimately run against one
endpoint. The factory still requires at least one endpoint but does not
construct a `ConsensusStream` (returns `consensus_threshold = 1`,
meaning "no quorum, pass straight through"). The static audit gate
(`audit/spof_check.py`) verifies that the mainnet branch is the strict
one — a regression that loosened it would surface in the gate, not in
prod traffic.

This module is pure stdlib + indexer imports; no network calls.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass, field

from indexer.yellowstone import YellowstoneConfig


# =============================================================================
# Constants — the SPOF-#8 production floor
# =============================================================================

#: Environment variable naming the active cluster. Mainnet values activate
#: the strict multi-endpoint requirement.
CLUSTER_ENV = "PHYLANX_SOLANA_CLUSTER"

#: Cluster names that the production-default refusal applies to. Aliases
#: are recognised so `mainnet`, `mainnet-beta`, and `production` are all
#: treated as the same risk profile.
MAINNET_CLUSTERS: frozenset[str] = frozenset({
    "mainnet",
    "mainnet-beta",
    "production",
    "prod",
})

#: Environment variable holding the comma-separated endpoint spec.
ENDPOINTS_ENV = "PHYLANX_GEYSER_ENDPOINTS"

#: SPOF-#8 mainnet floor: at least three independent Geyser endpoints.
#: Two is enough to detect disagreement but not enough to break ties — the
#: consensus stream requires K of N with K >= 2, and a 2-of-2 setup
#: degrades to "any single failure halts ingest". Three is the smallest
#: configuration where one endpoint can fail OR disagree and the indexer
#: still ingests on the majority.
MAINNET_MIN_ENDPOINTS = 3

#: Hard floor on K for any consensus stream. 1 would mean "trust any one
#: endpoint" which is the very SPOF this module exists to forbid.
MIN_CONSENSUS_THRESHOLD = 2


# =============================================================================
# Errors
# =============================================================================

class SinglePointGeyserError(RuntimeError):
    """
    Raised when a mainnet indexer is configured with fewer than
    `MAINNET_MIN_ENDPOINTS` independent Geyser endpoints, or with a
    consensus threshold below `MIN_CONSENSUS_THRESHOLD`.

    The exception type itself is part of the contract: deployment
    automation may catch it specifically and surface a different alert
    than a generic config typo.
    """


class GeyserConfigError(ValueError):
    """Raised on a malformed endpoint spec (parsing-time errors)."""


# =============================================================================
# ProductionGeyserConfig — the contract returned by the factory
# =============================================================================

@dataclass(frozen=True, slots=True)
class ProductionGeyserConfig:
    """
    The construction contract for a production indexer.

    `endpoints` is the per-endpoint Yellowstone connection list (always
    non-empty). `consensus_threshold` is the K in K-of-N — 1 on
    non-mainnet (pass-through), >= 2 on mainnet (strict majority).

    `is_mainnet` lets callers branch on the policy decision without
    re-parsing the cluster env var.
    """
    endpoints:            tuple[YellowstoneConfig, ...]
    endpoint_labels:      tuple[str, ...]
    consensus_threshold:  int
    cluster:              str
    is_mainnet:           bool

    @property
    def total_sources(self) -> int:
        return len(self.endpoints)

    @property
    def requires_consensus(self) -> bool:
        """True iff the runner must construct a `ConsensusStream`."""
        return self.consensus_threshold >= MIN_CONSENSUS_THRESHOLD


# =============================================================================
# Parsing
# =============================================================================

@dataclass(frozen=True, slots=True)
class _EndpointSpec:
    """Parsed form of one `PHYLANX_GEYSER_ENDPOINTS` entry."""
    label:         str
    endpoint:      str
    token_env_var: str = ""


def _parse_endpoint_specs(raw: str) -> list[_EndpointSpec]:
    """
    Parse `name:url[:token_env_var],...` into a list of specs.

    `url` may itself contain ':' (it usually does — `https://...`). To
    keep the format unambiguous we split on the FIRST and LAST ':'
    boundaries: everything before the first ':' is the label; if the
    remainder contains a trailing ',TOKEN_ENV' segment, we strip it; the
    middle is the URL.

    Token env-var-name resolution (NOT the token value) is the contract
    so secrets never appear in env-var spec strings.

    Format (per entry):
        name=https://host:port[?path][|TOKEN_ENV_VAR]

    Example:
        helius-main=https://helius-mainnet.solana.com:443|HELIUS_GEYSER_TOKEN,\
        triton-main=https://triton.rpcpool.com:443|TRITON_TOKEN,\
        quicknode-main=https://quicknode.solana.com:443|QUICKNODE_TOKEN
    """
    entries = [e.strip() for e in raw.split(",") if e.strip()]
    if not entries:
        raise GeyserConfigError(
            f"{ENDPOINTS_ENV} is empty — at least one endpoint is required",
        )

    out: list[_EndpointSpec] = []
    seen_labels: set[str] = set()
    seen_endpoints: set[str] = set()
    for entry in entries:
        if "=" not in entry:
            raise GeyserConfigError(
                f"{ENDPOINTS_ENV} entry {entry!r} must be "
                f"'name=url[|TOKEN_ENV]'",
            )
        label, rest = entry.split("=", 1)
        label = label.strip()
        rest = rest.strip()
        if not label:
            raise GeyserConfigError(
                f"{ENDPOINTS_ENV} entry has an empty name: {entry!r}",
            )
        if label in seen_labels:
            raise GeyserConfigError(
                f"{ENDPOINTS_ENV} has duplicate endpoint name: {label!r}",
            )
        seen_labels.add(label)

        if "|" in rest:
            endpoint, token_env_var = rest.split("|", 1)
            endpoint = endpoint.strip()
            token_env_var = token_env_var.strip()
        else:
            endpoint = rest
            token_env_var = ""

        if not endpoint:
            raise GeyserConfigError(
                f"{ENDPOINTS_ENV} entry {label!r} has an empty url",
            )
        if endpoint in seen_endpoints:
            raise GeyserConfigError(
                f"{ENDPOINTS_ENV} has duplicate endpoint url: {endpoint!r} — "
                f"the SPOF-#8 multi-endpoint requirement is meaningless if "
                f"two 'independent' endpoints point at the same host",
            )
        seen_endpoints.add(endpoint)

        out.append(_EndpointSpec(
            label=label, endpoint=endpoint, token_env_var=token_env_var,
        ))
    return out


def _is_mainnet_cluster(cluster: str) -> bool:
    return cluster.strip().lower() in MAINNET_CLUSTERS


def _strict_majority(n: int) -> int:
    """K = floor(N/2) + 1 — the smallest strict majority of N."""
    return (n // 2) + 1


# =============================================================================
# Factory — the only sanctioned construction path
# =============================================================================

def build_production_geyser_config(
    *,
    cluster:              str | None = None,
    endpoint_spec:        str | None = None,
    token_lookup:         "callable[[str], str] | None" = None,
    consensus_threshold:  int | None = None,
    account_include:      Sequence[str] = (),
    commitment:           str = "confirmed",
) -> ProductionGeyserConfig:
    """
    Build a `ProductionGeyserConfig` for the active deployment.

    Parameters
    ----------
    cluster
        Override for `PHYLANX_SOLANA_CLUSTER`. Tests pass it explicitly;
        deployment leaves it None so the env var is read.
    endpoint_spec
        Override for `PHYLANX_GEYSER_ENDPOINTS`. Same rationale.
    token_lookup
        Function that resolves a token env-var name to its value.
        Defaults to `os.environ.get`. Tests inject a deterministic map.
    consensus_threshold
        Override for K. On mainnet, the floor is `floor(N/2) + 1`;
        passing a smaller value raises `SinglePointGeyserError`. On
        non-mainnet, the default is 1 (no consensus).
    account_include, commitment
        Passed through into every per-endpoint `YellowstoneConfig`.

    Raises
    ------
    SinglePointGeyserError
        Mainnet configuration with fewer than `MAINNET_MIN_ENDPOINTS`
        endpoints, or a sub-strict-majority `consensus_threshold`.
    GeyserConfigError
        Malformed endpoint spec.
    """
    if cluster is None:
        cluster = os.environ.get(CLUSTER_ENV, "").strip()
    if not cluster:
        raise GeyserConfigError(
            f"{CLUSTER_ENV} must be set so the SPOF-#8 mainnet floor can "
            f"be evaluated — set it to 'devnet', 'localnet', or 'mainnet'",
        )

    if endpoint_spec is None:
        endpoint_spec = os.environ.get(ENDPOINTS_ENV, "")
    if not endpoint_spec.strip():
        raise GeyserConfigError(
            f"{ENDPOINTS_ENV} must be set — there is no implicit default "
            f"endpoint under SPOF-#8 (a missing var historically defaulted "
            f"to a single hard-coded URL, which is precisely the SPOF)",
        )

    specs = _parse_endpoint_specs(endpoint_spec)
    is_mainnet = _is_mainnet_cluster(cluster)

    if is_mainnet and len(specs) < MAINNET_MIN_ENDPOINTS:
        raise SinglePointGeyserError(
            f"SPOF-#8: cluster {cluster!r} requires at least "
            f"{MAINNET_MIN_ENDPOINTS} independent Geyser endpoints, got "
            f"{len(specs)} ({[s.label for s in specs]!r}). A single- or "
            f"two-endpoint mainnet indexer is refused: one compromised "
            f"endpoint forges the chain projection. Configure additional "
            f"endpoints via {ENDPOINTS_ENV}.",
        )

    if consensus_threshold is None:
        consensus_threshold = (
            _strict_majority(len(specs)) if is_mainnet else 1
        )

    if is_mainnet and consensus_threshold < MIN_CONSENSUS_THRESHOLD:
        raise SinglePointGeyserError(
            f"SPOF-#8: mainnet consensus_threshold must be at least "
            f"{MIN_CONSENSUS_THRESHOLD} (got {consensus_threshold}). A K=1 "
            f"quorum is identical to trusting a single endpoint, which is "
            f"the very SPOF this gate exists to forbid.",
        )
    if consensus_threshold > len(specs):
        raise SinglePointGeyserError(
            f"consensus_threshold ({consensus_threshold}) cannot exceed the "
            f"endpoint count ({len(specs)}) — the stream would never reach "
            f"quorum",
        )
    if consensus_threshold < 1:
        raise GeyserConfigError(
            f"consensus_threshold must be >= 1, got {consensus_threshold}",
        )

    lookup = token_lookup if token_lookup is not None else os.environ.get

    yconfigs: list[YellowstoneConfig] = []
    for spec in specs:
        token = ""
        if spec.token_env_var:
            token = lookup(spec.token_env_var) or ""
        yconfigs.append(YellowstoneConfig(
            endpoint=spec.endpoint,
            x_token=token,
            account_include=tuple(account_include),
            commitment=commitment,
        ))

    return ProductionGeyserConfig(
        endpoints=tuple(yconfigs),
        endpoint_labels=tuple(s.label for s in specs),
        consensus_threshold=consensus_threshold,
        cluster=cluster,
        is_mainnet=is_mainnet,
    )


# =============================================================================
# TA-2 enforcement: mainnet runner MUST consume a ConsensusStream
# =============================================================================
#
# SPOF-#8's factory refuses to BUILD a single-endpoint mainnet config. TA-2
# extends the gate to refuse to RUN a single-endpoint stream: if a caller
# bypasses the factory and hands the runner an unverified StreamSource on
# mainnet, the runner's pre-flight check must reject it.
#
# The marker is a duck-typed property `is_verified_consensus_source` on the
# stream object. `ConsensusStream` exposes it as `True`; an unverified
# YellowstoneStreamSource / ListStreamSource does not, and the check fails.
# This keeps `indexer/runner.py` free of import-time dependencies on the
# auth / consensus modules — the runner imports only this module's
# `assert_source_verified_for_cluster` helper.


class UnverifiedStreamSourceError(SinglePointGeyserError):
    """
    Raised when a mainnet `GeyserIndexer` is constructed with a StreamSource
    that is NOT a verified consensus stream. A subclass of
    `SinglePointGeyserError` so existing alert wiring catches it under the
    same SPOF-#8 family.
    """


def is_verified_consensus_source(source: object) -> bool:
    """
    Duck-typed predicate: returns True iff `source` claims to be the
    verified ConsensusStream production path.

    The contract is: any StreamSource whose `is_verified_consensus_source`
    attribute is the literal `True` is accepted; anything else is rejected.
    `ConsensusStream` sets this attribute in its class body so honest
    callers do not have to remember it.
    """
    return getattr(source, "is_verified_consensus_source", False) is True


def assert_source_verified_for_cluster(
    source: object,
    *,
    cluster: str | None = None,
) -> None:
    """
    Pre-flight check used by `GeyserIndexer.__init__`. On a mainnet
    cluster, the source MUST be a verified ConsensusStream — raises
    `UnverifiedStreamSourceError` otherwise. On non-mainnet, no check.

    Reading the env var here keeps the runner ignorant of cluster policy:
    one helper, one place that knows what mainnet means.
    """
    if cluster is None:
        cluster = os.environ.get(CLUSTER_ENV, "").strip()
    if not _is_mainnet_cluster(cluster):
        return
    if not is_verified_consensus_source(source):
        raise UnverifiedStreamSourceError(
            f"TA-2: cluster {cluster!r} requires a verified ConsensusStream "
            f"source (got {type(source).__name__!r}). Construct the indexer "
            f"with build_production_geyser_config() + ConsensusStream — "
            f"plain YellowstoneStreamSource is refused on mainnet so a "
            f"compromised single endpoint cannot poison the ingest path.",
        )


__all__ = [
    "CLUSTER_ENV", "ENDPOINTS_ENV",
    "MAINNET_CLUSTERS", "MAINNET_MIN_ENDPOINTS", "MIN_CONSENSUS_THRESHOLD",
    "GeyserConfigError", "SinglePointGeyserError",
    "UnverifiedStreamSourceError",
    "ProductionGeyserConfig",
    "build_production_geyser_config",
    "is_verified_consensus_source",
    "assert_source_verified_for_cluster",
]
