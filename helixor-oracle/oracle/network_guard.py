"""
oracle/network_guard.py — the mainnet refusal gate.

This is the launch-safety belt for every Helixor service. Entrypoints call
`enforce_network_guard()` before opening RPC connections or starting worker
loops. The guard asserts the configured Solana network is NOT mainnet,
unless `HELIXOR_MAINNET_OK` is explicitly set to `"1"`.

WHY ENTRYPOINT-INIT
-------------------
A "config check before doing anything" deferred to first RPC use is too
late — the wrong network may already be reached, an RPC keypair may
already be loaded, side effects may already have started. We refuse at
entrypoint startup, before those effects. The cost is a single env-var
read; the benefit is that no service can accidentally start against
mainnet without an explicit, loud, audited opt-in.

WHY AN EXPLICIT FLAG
--------------------
Mainnet is reachable. We do not want to make it unreachable — that would
mean Helixor can never run in production. We want every mainnet start to
be a CONSCIOUS DECISION: someone set the env var, the log line proves
they did, and an external auditor can grep for the decision in service
logs.

USAGE
-----
At the top of every entrypoint module (cluster node, indexer service,
API server, RPC submitter):

    from oracle.network_guard import enforce_network_guard
    enforce_network_guard()  # raises ProductionRefused on misconfig

In tests, this is a no-op — `HELIXOR_NETWORK` is unset, refusal only
fires when an entrypoint sets `HELIXOR_NETWORK=mainnet-beta` without
also setting `HELIXOR_MAINNET_OK=1`.

THE SUPPORTED NETWORKS
----------------------
  localnet       — bench / local validator
  devnet         — public devnet
  testnet        — public testnet
  mainnet-beta   — production (refused unless HELIXOR_MAINNET_OK=1)

DETERMINISM
-----------
The guard reads only env vars and performs no network I/O. Tests that
need to flip the verdict use the `override_network` context manager.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from dataclasses import dataclass


logger = logging.getLogger("helixor.network_guard")


# =============================================================================
# The supported network identifiers
# =============================================================================

NETWORK_LOCALNET     = "localnet"
NETWORK_DEVNET       = "devnet"
NETWORK_TESTNET      = "testnet"
NETWORK_MAINNET_BETA = "mainnet-beta"

SUPPORTED_NETWORKS = frozenset({
    NETWORK_LOCALNET, NETWORK_DEVNET, NETWORK_TESTNET, NETWORK_MAINNET_BETA,
})

# Networks for which the guard refuses to start without an explicit opt-in.
PRODUCTION_NETWORKS = frozenset({NETWORK_MAINNET_BETA})

# The env vars the guard reads.
ENV_NETWORK    = "HELIXOR_NETWORK"
ENV_MAINNET_OK = "HELIXOR_MAINNET_OK"

# The default network if HELIXOR_NETWORK is unset. We default to LOCALNET
# rather than DEVNET so a misconfigured test environment cannot
# accidentally talk to a public cluster.
DEFAULT_NETWORK = NETWORK_LOCALNET


# =============================================================================
# Exceptions
# =============================================================================

class ProductionRefused(RuntimeError):
    """
    Raised when the guard refuses to start because the configured network
    is a production cluster and no opt-in was given.
    """


class UnsupportedNetwork(RuntimeError):
    """Raised when HELIXOR_NETWORK is set to an unrecognised value."""


# =============================================================================
# The verdict
# =============================================================================

@dataclass(frozen=True, slots=True)
class NetworkVerdict:
    """The guard's decision — exposed so callers can inspect it."""
    network:     str
    is_production: bool
    opted_in:    bool

    @property
    def must_refuse(self) -> bool:
        return self.is_production and not self.opted_in


def current_network() -> str:
    """The network the guard sees. Falls back to LOCALNET if unset."""
    return os.environ.get(ENV_NETWORK, DEFAULT_NETWORK).strip()


def opted_in_to_mainnet() -> bool:
    """True iff HELIXOR_MAINNET_OK is set to `"1"`."""
    return os.environ.get(ENV_MAINNET_OK, "").strip() == "1"


def evaluate() -> NetworkVerdict:
    """
    Compute the current verdict — what the guard would do if asked to
    enforce now. Safe to call from anywhere; does not raise.
    """
    network = current_network()
    if network not in SUPPORTED_NETWORKS:
        raise UnsupportedNetwork(
            f"{ENV_NETWORK}={network!r} is not in "
            f"{sorted(SUPPORTED_NETWORKS)} — set explicitly"
        )
    return NetworkVerdict(
        network=network,
        is_production=network in PRODUCTION_NETWORKS,
        opted_in=opted_in_to_mainnet(),
    )


# =============================================================================
# The gate
# =============================================================================

def enforce_network_guard(*, service: str | None = None) -> NetworkVerdict:
    """
    Enforce the network guard. Returns the verdict on success; raises
    `ProductionRefused` if the network is production and no opt-in was
    given, or `UnsupportedNetwork` if the value is unrecognised.

    `service` names the calling entrypoint, only used for the log line.
    """
    verdict = evaluate()
    label = service or "<unspecified>"

    if verdict.must_refuse:
        msg = (
            f"network_guard: REFUSING to start service {label!r} against "
            f"network {verdict.network!r} without an explicit opt-in. "
            f"Set {ENV_MAINNET_OK}=1 in the environment to acknowledge "
            f"this is a production start. This is the last safety belt "
            f"before mainnet — read "
            f"launch/runbooks/mainnet_refusal_triggered.md before overriding."
        )
        logger.error(msg)
        raise ProductionRefused(msg)

    if verdict.is_production:
        # opted-in mainnet — log loudly so the decision is auditable.
        logger.warning(
            "network_guard: service %s is starting against PRODUCTION "
            "network %s with explicit HELIXOR_MAINNET_OK=1 opt-in",
            label, verdict.network,
        )
    else:
        logger.info(
            "network_guard: service %s starting against %s (non-production)",
            label, verdict.network,
        )
    return verdict


# =============================================================================
# Test helper — flip the verdict for a block of code
# =============================================================================

@contextmanager
def override_network(network: str, *, mainnet_ok: bool = False):
    """
    Temporarily override the network env vars for a test. Restores the
    previous values on exit, even if the test raises.

    Usage:
        with override_network("mainnet-beta"):
            with pytest.raises(ProductionRefused):
                enforce_network_guard(service="ut")
    """
    prev_net = os.environ.get(ENV_NETWORK)
    prev_ok  = os.environ.get(ENV_MAINNET_OK)
    os.environ[ENV_NETWORK] = network
    if mainnet_ok:
        os.environ[ENV_MAINNET_OK] = "1"
    elif ENV_MAINNET_OK in os.environ:
        del os.environ[ENV_MAINNET_OK]
    try:
        yield
    finally:
        if prev_net is None:
            os.environ.pop(ENV_NETWORK, None)
        else:
            os.environ[ENV_NETWORK] = prev_net
        if prev_ok is None:
            os.environ.pop(ENV_MAINNET_OK, None)
        else:
            os.environ[ENV_MAINNET_OK] = prev_ok
