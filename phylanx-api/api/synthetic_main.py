"""
api/synthetic_main.py — local seeded API entrypoint.

Run this when you want the frontend to exercise the real API contract
without a TimescaleDB instance:

    PYTHONPATH=.:../phylanx-oracle PHYLANX_SYNTHETIC_AGENTS=50 \
      python -m api.synthetic_main

Production must use api.main; this entrypoint is deliberately local-only.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from oracle.network_guard import (
    ProductionRefused,
    UnsupportedNetwork,
    enforce_network_guard,
)


logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("phylanx.api.synthetic")


try:
    _VERDICT = enforce_network_guard(service="phylanx-api-synthetic")
except (ProductionRefused, UnsupportedNetwork) as exc:
    logger.error(str(exc))
    sys.exit(2)

if _VERDICT.is_production:
    logger.error("synthetic API refuses production networks even with opt-in")
    sys.exit(2)


from api.app import create_app                                      # noqa: E402
from api.auth import ApiKeyRegistry, load_keys_from_env             # noqa: E402
from api.synthetic_seed import build_synthetic_repos, write_explanation_report  # noqa: E402


def build_app():
    count = int(os.environ.get("PHYLANX_SYNTHETIC_AGENTS", "50"))
    score_repo, byz_repo, cluster_repo, explanations = build_synthetic_repos(
        count=count,
    )
    report_path = Path(os.environ.get(
        "PHYLANX_SYNTHETIC_REPORT",
        "/tmp/phylanx_synthetic_report.json",
    ))
    write_explanation_report(explanations, report_path)
    logger.info(
        "seeded synthetic API with %d agents; explanation report=%s",
        count, report_path,
    )
    return create_app(
        score_repo=score_repo,
        byzantine_repo=byz_repo,
        cluster_repo=cluster_repo,
        key_registry=ApiKeyRegistry(load_keys_from_env()),
        network=_VERDICT.network,
        is_production=False,
        scoring_algo_version="synthetic-v2-real-engine",
        scoring_weights_version="w1",
    )


app = build_app()


def main() -> int:
    import uvicorn

    port = int(os.environ.get("PHYLANX_API_PORT", "8080"))
    host = os.environ.get("PHYLANX_API_HOST", "127.0.0.1")
    logger.info("synthetic phylanx-api starting on %s:%d", host, port)
    uvicorn.run("api.synthetic_main:app", host=host, port=port, access_log=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
