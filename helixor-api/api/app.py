"""
api/app.py — the FastAPI application.

`create_app` builds a fresh FastAPI instance wired to the supplied
repositories. Tests pass in-memory repos; the production entrypoint
(api/main.py) constructs the TimescaleDB-backed repos and passes those.

WHY A FACTORY, NOT A MODULE-LEVEL `app`
---------------------------------------
Module-level state is hostile to testing: every test imports the same
`app`, so wiring different repos per test requires monkey-patching or
dependency-overrides. A factory takes the repos as arguments, so every
test gets a fresh, isolated app. The production entrypoint calls the
factory ONCE at startup.

WIRING THE NETWORK GUARD
------------------------
The guard fires at module-import in api/main.py. The factory itself
records the network in the metric set so dashboards can display it,
but does not re-enforce — the guard is a process-level decision, not a
per-request check.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from api import __version__
from api.byzantine_repo import ByzantineRepository
from api.cluster_health import ClusterHealthRepository
from api.metrics import (
    ApiMetrics, CollectorRegistry, make_registry, render_metrics,
)
from api.schemas import (
    SCHEMA_VERSION,
    ByzantineFlagEntry,
    ByzantineRecentResponse,
    ChallengeEntry,
    ChallengesResponse,
    ClusterHealthResponse,
    EpochSummaryEntry,
    ErrorResponse,
    HealthResponse,
    HeartbeatEntry,
    HistoryEntry,
    HistoryResponse,
    PerNodeRevealEntry,
    PerNodeRevealsResponse,
    StrikeEntry,
    StrikeSummaryResponse,
    VersionResponse,
)
from api.score_repo import ScoreRecord, ScoreRepository


# =============================================================================
# Alert tier code → label
# =============================================================================

_TIER_LABEL = {0: "GREEN", 1: "YELLOW", 2: "RED"}


def _tier(code: int) -> str:
    return _TIER_LABEL.get(code, f"UNKNOWN({code})")


# =============================================================================
# Score record → response shape
# =============================================================================

def _to_health(rec: ScoreRecord) -> HealthResponse:
    return HealthResponse(
        agent_wallet=rec.agent_wallet,
        epoch=rec.epoch,
        score=rec.score,
        alert_tier=_tier(rec.alert_tier),
        alert_tier_code=rec.alert_tier,
        flags=rec.flags,
        immediate_red=rec.immediate_red,
        signer_count=rec.signer_count,
        computed_at=rec.computed_at,
    )


def _to_history_entry(rec: ScoreRecord) -> HistoryEntry:
    return HistoryEntry(
        epoch=rec.epoch,
        score=rec.score,
        alert_tier=_tier(rec.alert_tier),
        alert_tier_code=rec.alert_tier,
        immediate_red=rec.immediate_red,
        signer_count=rec.signer_count,
        computed_at=rec.computed_at,
    )


# =============================================================================
# The factory
# =============================================================================

def create_app(
    *,
    score_repo:      ScoreRepository,
    byzantine_repo:  ByzantineRepository,
    cluster_repo:    ClusterHealthRepository,
    network:         str            = "localnet",
    is_production:   bool           = False,
    scoring_algo_version:    str | None = None,
    scoring_weights_version: str | None = None,
    metrics_registry: CollectorRegistry | None = None,
) -> FastAPI:
    """Build the FastAPI app wired to the supplied repos."""

    registry = metrics_registry if metrics_registry is not None else make_registry()
    metrics  = ApiMetrics(registry)
    metrics.is_production.set(1 if is_production else 0)
    metrics.schema_version.set(SCHEMA_VERSION)

    app = FastAPI(
        title="Helixor V2 API",
        description="Read-side cache for Helixor agent health certificates.",
        version=__version__,
    )

    # ── Middleware: per-request latency + counter ───────────────────────────

    @app.middleware("http")
    async def _record_metrics(request: Request, call_next):
        # Resolve the route template (not the literal path) so per-agent
        # cardinality doesn't explode the metric — `/agents/{wallet}/health`
        # rather than `/agents/<actual wallet>/health`.
        method = request.method
        started = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - started
        route_template = _route_template(request)
        metrics.request_seconds.labels(method, route_template).observe(elapsed)
        metrics.requests_total.labels(
            method, route_template, str(response.status_code),
        ).inc()
        return response

    # ── Error handler — guarantee the JSON shape ────────────────────────────

    @app.exception_handler(HTTPException)
    async def _http_exc(_request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error=_default_error_name(exc.status_code),
                detail=str(exc.detail),
            ).model_dump(),
        )

    # ── Routes ──────────────────────────────────────────────────────────────

    @app.get("/agents/{wallet}/health", response_model=HealthResponse)
    def agent_health(wallet: str) -> HealthResponse:
        rec = score_repo.latest_score(wallet)
        if rec is None:
            raise HTTPException(404, f"no score recorded for {wallet}")
        return _to_health(rec)

    @app.get("/agents/{wallet}/health/{epoch}", response_model=HealthResponse)
    def agent_health_at_epoch(wallet: str, epoch: int) -> HealthResponse:
        if epoch < 1:
            raise HTTPException(400, "epoch must be >= 1")
        rec = score_repo.score_at_epoch(wallet, epoch)
        if rec is None:
            raise HTTPException(404, f"no score for {wallet} at epoch {epoch}")
        return _to_health(rec)

    @app.get("/agents/{wallet}/history", response_model=HistoryResponse)
    def agent_history(
        wallet: str,
        from_epoch: int | None = None,
        to_epoch:   int | None = None,
        limit:      int = 100,
    ) -> HistoryResponse:
        if limit < 1 or limit > 1000:
            raise HTTPException(400, "limit must be 1..1000")
        if from_epoch is not None and from_epoch < 1:
            raise HTTPException(400, "from_epoch must be >= 1")
        if to_epoch is not None and from_epoch is not None \
           and to_epoch < from_epoch:
            raise HTTPException(400, "to_epoch must be >= from_epoch")
        records = score_repo.score_history(
            wallet,
            from_epoch=from_epoch, to_epoch=to_epoch, limit=limit,
        )
        return HistoryResponse(
            agent_wallet=wallet,
            entries=[_to_history_entry(r) for r in records],
            from_epoch=from_epoch, to_epoch=to_epoch, limit=limit,
        )

    @app.get("/byzantine/recent", response_model=ByzantineRecentResponse)
    def byzantine_recent(
        since_epoch: int | None = None, limit: int = 100,
    ) -> ByzantineRecentResponse:
        if limit < 1 or limit > 1000:
            raise HTTPException(400, "limit must be 1..1000")
        flags = byzantine_repo.recent_flags(
            since_epoch=since_epoch, limit=limit,
        )
        return ByzantineRecentResponse(
            since_epoch=since_epoch,
            flags=[
                ByzantineFlagEntry(
                    node=f.node_id, epoch=f.epoch,
                    subject_agent=f.subject_agent,
                    accused_score=f.accused_score,
                    cluster_median=f.cluster_median,
                    deviation=f.deviation,
                )
                for f in flags
            ],
        )

    @app.get("/byzantine/strikes", response_model=StrikeSummaryResponse)
    def byzantine_strikes() -> StrikeSummaryResponse:
        rows = byzantine_repo.strike_summary()
        return StrikeSummaryResponse(
            summary={
                row.node_id: StrikeEntry(
                    strikes=row.strikes,
                    flagged_epochs=list(row.flagged_epochs),
                    challenged=row.challenged,
                )
                for row in rows
            },
        )

    @app.get("/byzantine/per_node", response_model=PerNodeRevealsResponse)
    def byzantine_per_node(
        epoch: int, agent: str,
    ) -> PerNodeRevealsResponse:
        if epoch < 1:
            raise HTTPException(400, "epoch must be >= 1")
        reveals = byzantine_repo.per_node_reveals(epoch=epoch, agent_wallet=agent)
        return PerNodeRevealsResponse(
            epoch=epoch, agent=agent,
            reveals=[
                PerNodeRevealEntry(node=r.node_id, score=r.score)
                for r in reveals
            ],
        )

    @app.get("/challenges", response_model=ChallengesResponse)
    def challenges(node: str) -> ChallengesResponse:
        rows = byzantine_repo.challenges_for(node)
        return ChallengesResponse(
            accused_node=node,
            challenges=[
                ChallengeEntry(
                    challenge_index=c.challenge_index,
                    accused_node=c.accused_node,
                    proof_type=c.proof_type,
                    subject_epoch=c.subject_epoch,
                    subject_agent=c.subject_agent,
                    accused_score=c.accused_score,
                    cluster_median=c.cluster_median,
                    evidence_hash=c.evidence_hash,
                    status=c.status,
                    filed_at=c.filed_at,
                )
                for c in rows
            ],
        )

    @app.get("/health/cluster", response_model=ClusterHealthResponse)
    def cluster_health(limit: int = 10) -> ClusterHealthResponse:
        if limit < 1 or limit > 1000:
            raise HTTPException(400, "limit must be 1..1000")
        return ClusterHealthResponse(
            heartbeats=[
                HeartbeatEntry(
                    node=h.node_id,
                    last_seen_unix=h.last_seen_unix,
                    epoch=h.epoch,
                )
                for h in cluster_repo.heartbeats()
            ],
            recent_epochs=[
                EpochSummaryEntry(
                    epoch=e.epoch,
                    submitted_count=e.submitted_count,
                    agent_count=e.agent_count,
                    verified_nodes=list(e.verified_nodes),
                    byzantine_nodes=list(e.byzantine_nodes),
                    unreachable_nodes=list(e.unreachable_nodes),
                    elapsed_seconds=e.elapsed_seconds,
                    computed_at=e.computed_at,
                )
                for e in cluster_repo.recent_epochs(limit=limit)
            ],
        )

    @app.get("/version", response_model=VersionResponse)
    def version() -> VersionResponse:
        return VersionResponse(
            api_version=__version__,
            scoring_algo_version=scoring_algo_version,
            scoring_weights_version=scoring_weights_version,
            network=network,
            network_is_production=is_production,
        )

    @app.get("/health")
    def health_liveness() -> dict:
        # Standard k8s/systemd liveness — fast, no I/O.
        return {"status": "ok", "schema_version": SCHEMA_VERSION}

    @app.get("/metrics")
    def metrics_endpoint() -> Response:
        data, content_type = render_metrics(registry)
        return Response(content=data, media_type=content_type)

    # Hang the metrics + registry off the app for tests to inspect.
    app.state.metrics = metrics
    app.state.registry = registry
    return app


# =============================================================================
# Helpers
# =============================================================================

def _route_template(request: Request) -> str:
    """Resolve the route template for a request — `/agents/{wallet}/health`,
    not `/agents/<actual wallet>/health` — so the metric label cardinality
    stays bounded."""
    route = request.scope.get("route")
    if route is not None and hasattr(route, "path"):
        return route.path
    # Fallback for requests that didn't match a route — group them.
    return "<unmatched>"


def _default_error_name(status: int) -> str:
    return {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        429: "too_many_requests",
        500: "internal_error",
    }.get(status, f"http_{status}")
