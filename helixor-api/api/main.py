"""
api/main.py — production entrypoint.

This is the file referenced by the systemd unit and the docker-compose
service. It:

  1. ENFORCES THE NETWORK GUARD at module-import time. If
     HELIXOR_NETWORK=mainnet-beta and HELIXOR_MAINNET_OK is not set,
     this module fails to import and the process exits with code 2.
     The systemd unit's RestartPreventExitStatus=2 stops the loop —
     the misconfig fails loud and stationary, not in a thrashing retry.

  2. Constructs the production repositories. If DATABASE_URL is set,
     the service opens the Timescale/Postgres-backed read adapters and
     creates the read-side schema idempotently. A DB misconfiguration is
     fatal; production must not silently serve empty in-memory data.

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
from api.byzantine_repo import InMemoryByzantineRepo                # noqa: E402
from api.cluster_health import InMemoryClusterHealthRepo            # noqa: E402
from api.score_repo import InMemoryScoreRepo                        # noqa: E402


# =============================================================================
# Repository construction
# =============================================================================

def _build_repos():
    """
    Construct the production repos.

    No DATABASE_URL means explicit local/dev mode: empty in-memory repos.
    DATABASE_URL set means production-shaped mode: open the database
    adapters or fail the process. This prevents the dangerous half-state
    where production is configured with a DB but the API quietly serves
    empty memory data.
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

    from api._timescale import open_repos

    try:
        repos = open_repos(db_url)
    except Exception:
        logger.exception(
            "DATABASE_URL is set but Helixor could not open the "
            "Timescale/Postgres read adapters. Refusing to start instead "
            "of serving fake empty data."
        )
        raise

    logger.info("using Timescale/Postgres-backed read repositories")
    return repos


# =============================================================================
# App construction (exported so uvicorn / tests can import `api.main:app`)
# =============================================================================

def build_app():
    score_repo, byzantine_repo, cluster_repo = _build_repos()
    return create_app(
        score_repo=score_repo,
        byzantine_repo=byzantine_repo,
        cluster_repo=cluster_repo,
        network=_VERDICT.network,
        is_production=_VERDICT.is_production,
        scoring_algo_version=os.environ.get("SCORING_ALGO_VERSION"),
        scoring_weights_version=os.environ.get("SCORING_WEIGHTS_VERSION"),
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
