"""
api/main.py — production entrypoint.

This is the file referenced by the systemd unit and the docker-compose
service. It:

  1. ENFORCES THE NETWORK GUARD at module-import time. If
     HELIXOR_NETWORK=mainnet-beta and HELIXOR_MAINNET_OK is not set,
     this module fails to import and the process exits with code 2.
     The systemd unit's RestartPreventExitStatus=2 stops the loop —
     the misconfig fails loud and stationary, not in a thrashing retry.

  2. Constructs the production-shape repositories. Today those are
     TimescaleDB-backed; a clean adapter layer (TimescaleScoreRepo,
     TimescaleByzantineRepo, TimescaleClusterHealthRepo) sits over the
     existing helixor-oracle/db/timescale_repo.py connection. Until the
     `agent_score_history`, `byzantine_flags`, and `oracle_heartbeats`
     hypertables exist in production, this entrypoint falls back to
     empty in-memory repos, logs a WARNING, and serves 404s for reads —
     so the API is bring-up-able BEFORE the indexer has produced any
     data, and the failure mode is honest.

  3. Builds the FastAPI app via the factory.

  4. Runs uvicorn on the configured port.

OPERATIONAL CONTRACT
--------------------
The systemd unit (launch/deploy/systemd/helixor-api.service) sets:

    HELIXOR_NETWORK       = devnet | mainnet-beta | ...
    HELIXOR_MAINNET_OK    = 1  (only when mainnet is intended)
    HELIXOR_API_PORT      = 8080
    HELIXOR_METRICS_PORT  = 9090
    DATABASE_URL          = postgres://...
    SCORING_ALGO_VERSION  = v2.7   (matches the cluster's pinned version)
    SCORING_WEIGHTS_VERSION = w1

In dev, the same module runs against an empty in-memory backend:

    python -m api.main
"""

from __future__ import annotations

import logging
import os
import sys


logger = logging.getLogger("helixor.api.main")


# =============================================================================
# Network guard — MODULE-INIT enforcement
# =============================================================================
#
# We import the oracle's network_guard module (single source of truth)
# rather than duplicating its env-var contract. The import path goes via
# the shared `helixor-oracle` package on PYTHONPATH; both production and
# dev environments have it on the path.

try:
    from oracle.network_guard import (
        ProductionRefused,
        UnsupportedNetwork,
        enforce_network_guard,
    )
except ImportError as exc:                       # pragma: no cover
    print(
        f"FATAL: cannot import oracle.network_guard ({exc}). "
        f"helixor-oracle must be on PYTHONPATH.",
        file=sys.stderr,
    )
    sys.exit(2)


def _enforce_or_exit() -> object:
    """Call the guard at import time. Exit 2 on refusal so systemd's
    RestartPreventExitStatus=2 keeps the misconfig stationary."""
    try:
        return enforce_network_guard(service="helixor-api")
    except ProductionRefused as exc:
        # The error message itself is the runbook — print it loud.
        logger.error(str(exc))
        sys.exit(2)
    except UnsupportedNetwork as exc:
        logger.error(str(exc))
        sys.exit(2)


# Configure logging BEFORE the guard runs so the refusal is captured.
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

_VERDICT = _enforce_or_exit()


# =============================================================================
# Imports that come AFTER the guard
# =============================================================================
#
# Anything that touches a network or could leak credentials must be
# imported below this line, never above. If the guard refuses we exit
# before we ever evaluate those imports.

from api import __version__                                         # noqa: E402
from api.app import create_app                                      # noqa: E402
from api.auth import ApiKeyRegistry, load_keys_from_env             # noqa: E402
from api.byzantine_repo import InMemoryByzantineRepo                # noqa: E402
from api.cluster_health import InMemoryClusterHealthRepo            # noqa: E402
from api.rate_limit import (                                        # noqa: E402
    load_public_limit_from_env,
    load_trust_proxy_from_env,
)
from api.score_repo import InMemoryScoreRepo                        # noqa: E402


# =============================================================================
# Repository construction
# =============================================================================

def _build_repos():
    """
    Construct the production repos. Today these are STUBS pending the
    TimescaleDB adapter layer:

      helixor-api/api/_timescale.py::TimescaleScoreRepo
      helixor-api/api/_timescale.py::TimescaleByzantineRepo
      helixor-api/api/_timescale.py::TimescaleClusterHealthRepo

    Each adapts the existing helixor-oracle/db/timescale_repo.py
    connection over three new tables the indexer populates:

        agent_score_history    (one row per cert the indexer mirrored)
        byzantine_flags        (one row per watchdog flag event)
        oracle_heartbeats      (last-seen per node)

    Until those tables exist, this returns empty in-memory repos so the
    service can be brought up (Phase-1 canary "bring up the operational
    stack against mainnet before producing certs") without crashing.
    """
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        logger.warning(
            "no DATABASE_URL set — falling back to empty in-memory repos. "
            "This is the expected mode for the Phase-1 canary; ALL READS "
            "will return 404 until the indexer is wired in."
        )
        return (
            InMemoryScoreRepo(),
            InMemoryByzantineRepo(),
            InMemoryClusterHealthRepo(),
        )

    # The TimescaleDB-backed implementations are deferred — when they
    # land, replace this branch with:
    #
    #     from api._timescale import open_repos
    #     return open_repos(db_url)
    #
    # The factory contract (3 protocol-conforming objects) is stable.
    logger.warning(
        "DATABASE_URL is set but the Timescale-backed adapters "
        "(api._timescale) have not landed yet. Falling back to empty "
        "in-memory repos. Reads will return 404. See helixor-api/README.md "
        "section 'Production wiring' for the remaining work."
    )
    return (
        InMemoryScoreRepo(),
        InMemoryByzantineRepo(),
        InMemoryClusterHealthRepo(),
    )


# =============================================================================
# App construction (exported so uvicorn / tests can import `api.main:app`)
# =============================================================================

def build_app():
    score_repo, byzantine_repo, cluster_repo = _build_repos()

    # VULN-09: load API keys + rate-limit config from the environment.
    # An empty HELIXOR_API_KEYS is a legitimate (if locked-down) state —
    # operational endpoints will then 401 every request and only the
    # public score-read endpoints answer.
    api_keys = load_keys_from_env()
    if not api_keys and _VERDICT.is_production:
        logger.warning(
            "VULN-09: production start with no HELIXOR_API_KEYS — "
            "operational endpoints (/health/cluster, /byzantine/*, "
            "/challenges) will reject every caller. Set HELIXOR_API_KEYS "
            "to one or more `key_id:secret[:tier[:limit_per_min]]` lines "
            "to enable them."
        )
    key_registry = ApiKeyRegistry(api_keys)
    trust_proxy  = load_trust_proxy_from_env()
    public_limit = load_public_limit_from_env()
    logger.info(
        "VULN-09 wiring: %d API key(s) registered, "
        "public_rate_limit=%d/min, trust_proxy=%s",
        len(key_registry), public_limit, trust_proxy,
    )

    return create_app(
        score_repo=score_repo,
        byzantine_repo=byzantine_repo,
        cluster_repo=cluster_repo,
        network=_VERDICT.network,
        is_production=_VERDICT.is_production,
        scoring_algo_version=os.environ.get("SCORING_ALGO_VERSION"),
        scoring_weights_version=os.environ.get("SCORING_WEIGHTS_VERSION"),
        key_registry=key_registry,
        public_rate_limit_per_minute=public_limit,
        trust_proxy=trust_proxy,
    )


app = build_app()


# =============================================================================
# uvicorn entrypoint
# =============================================================================

def main() -> int:
    import uvicorn

    port    = int(os.environ.get("HELIXOR_API_PORT", "8080"))
    host    = os.environ.get("HELIXOR_API_HOST", "0.0.0.0")
    workers = int(os.environ.get("HELIXOR_API_WORKERS", "1"))

    logger.info(
        "helixor-api %s starting on %s:%d (network=%s, production=%s, workers=%d)",
        __version__, host, port, _VERDICT.network, _VERDICT.is_production, workers,
    )

    # Single-process for dev; production uses N workers via the systemd
    # unit's `--workers` argument or a process supervisor.
    uvicorn.run(
        "api.main:app",
        host=host, port=port, workers=workers,
        access_log=False,           # we record latencies in middleware
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
