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
from api.auth import ApiKey, ApiKeyRegistry, require_api_key
from api.webhooks import (
    CertDegradingPayload,
    CertDegradingTracker,
    EVENT_CERT_DEGRADING,
    NullDispatcher,
    WEBHOOK_SCHEMA_VERSION,
    WebhookDispatcher,
    WebhookRegistry,
    degrading_threshold_seconds,
)
from api.byzantine_repo import ByzantineRepository
from api.cluster_health import ClusterHealthRepository
from api.diagnosis_repo import DiagnosisRecord, DiagnosisRepository
from api.flag_obfuscation import compute_flag_token, popcount
from api.metrics import (
    ApiMetrics, CollectorRegistry, make_registry, render_metrics,
)
from api.rate_limit import (
    DEFAULT_PUBLIC_RATE_LIMIT_PER_MIN,
    SlidingWindowLimiter,
    client_ip,
)
from api.safe_score import (
    CERT_MAX_AGE_SECONDS,
    SafeScoreOk,
    compute_safe_score,
)
from api.schemas import (
    SCHEMA_VERSION,
    ByzantineFlagEntry,
    ByzantineRecentResponse,
    ChallengeEntry,
    ChallengesResponse,
    ClusterHealthResponse,
    DecodedFlagLabel,
    DiagnosisResponse,
    DimensionBreakdownEntry,
    EpochSummaryEntry,
    ErrorResponse,
    HealthResponse,
    IntegrationLeaderboardEntry,
    IntegrationLeaderboardResponse,
    HeartbeatEntry,
    HistoryEntry,
    HistoryResponse,
    PerNodeRevealEntry,
    PerNodeRevealsResponse,
    RemediationHint,
    SafeScoreResponse,
    SafeScoreVelocityWindow,
    StrikeEntry,
    StrikeSummaryResponse,
    VersionResponse,
)
from api.score_repo import ScoreRecord, ScoreRepository
from api.validation import validate_wallet

from diagnosis import (
    LABEL_METADATA,
    RemediationCode,
    Severity,
    decode,
    default_remediation,
    severity_of,
)
from diagnosis.taxonomy import FailureMode


# =============================================================================
# Alert tier code → label
# =============================================================================

_TIER_LABEL = {0: "GREEN", 1: "YELLOW", 2: "RED"}


def _tier(code: int) -> str:
    return _TIER_LABEL.get(code, f"UNKNOWN({code})")


# =============================================================================
# Cache-Control policy (VULN-09)
# =============================================================================
#
# Score reads are CDN-cacheable for 5 minutes. The audit asked for this
# explicitly — an upstream CDN that honours the header is the cheap fix
# for enumeration cost. `stale-while-revalidate` lets the CDN keep
# serving the previous body for an extra minute while it refreshes.
SCORE_CACHE_CONTROL = "public, max-age=300, stale-while-revalidate=60"

# Operational data must not be CDN-cached — it leaks oracle topology
# and ongoing investigations. `no-store` so no intermediary keeps a copy.
OPERATIONAL_CACHE_CONTROL = "private, no-store"

# Liveness + metrics + version are always cheap and never cached.
META_CACHE_CONTROL = "no-store"

# Paths that the rate limiter does NOT charge. k8s liveness and
# Prometheus scrapes must always answer; the docs surface is static.
_UNMETERED_PREFIXES = ("/docs", "/openapi", "/redoc")
_UNMETERED_EXACT    = frozenset({"/health", "/metrics"})


def _is_unmetered(path: str) -> bool:
    if path in _UNMETERED_EXACT:
        return True
    return any(path.startswith(prefix) for prefix in _UNMETERED_PREFIXES)


# =============================================================================
# DBP-4 — safe-reader-share surface classification
# =============================================================================
#
# The leaderboard ranks Verified Integrators by how often they call the
# guard-railed `safe_score` endpoint vs the raw `health` / `history`
# endpoints. We bucket by route_template (not literal path) so per-agent
# cardinality stays bounded.
#
# A route NOT in either set is unbucketed (e.g. /version, /byzantine/*,
# /metrics). The leaderboard ignores those — they don't represent
# value-bearing reads.

SAFE_SCORE_ROUTES: frozenset[str] = frozenset({
    "/agents/{wallet}/safe_score",
})
RAW_SCORE_ROUTES: frozenset[str] = frozenset({
    "/agents/{wallet}/health",
    "/agents/{wallet}/health/{epoch}",
    "/agents/{wallet}/history",
})


def _surface_for_route(route_template: str) -> str | None:
    if route_template in SAFE_SCORE_ROUTES:
        return "safe"
    if route_template in RAW_SCORE_ROUTES:
        return "raw"
    return None


# =============================================================================
# Score record → response shape
# =============================================================================

def _to_health(rec: ScoreRecord) -> HealthResponse:
    # VULN-24 mitigation #4: do NOT echo `rec.flags` directly. Map the
    # bitmask to an opaque token + popcount so an attacker cannot read
    # back exactly which detectors fired and craft the next input
    # around them.
    return HealthResponse(
        agent_wallet=rec.agent_wallet,
        epoch=rec.epoch,
        score=rec.score,
        alert_tier=_tier(rec.alert_tier),
        alert_tier_code=rec.alert_tier,
        flag_set_token=compute_flag_token(
            flags=rec.flags, agent_wallet=rec.agent_wallet, epoch=rec.epoch,
        ),
        flag_count=popcount(rec.flags),
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
# Diagnosis record → response shape (Day 34, Phase-1 off-chain)
# =============================================================================

def _to_diagnosis(rec: DiagnosisRecord) -> DiagnosisResponse:
    """Project a `DiagnosisRecord` into the wire shape, decoding the
    legacy u32 flag bitmask through the Day-33 taxonomy so the response
    carries both the raw bits and the human-readable labels.

    The flag exposure here is INTENTIONALLY less obfuscated than the
    `HealthResponse` surface — the diagnosis endpoint exists to *explain*
    failure modes, so the labels (and the underlying u32 bitmask) ARE
    the product. VULN-24's adversarial-ML rationale does not apply: a
    consumer reading diagnosis output is the operator the surface is
    built for, not the adversary the score-only endpoint protected
    against. The Day-33 attestation tag (`off_chain_v1`) tells the
    consumer this tier is not threshold-signed yet.
    """
    decoded = decode(rec.flags)
    known_bits = {label.bit for label in decoded}
    set_bits = _bit_positions(rec.flags)
    undecoded = [b for b in set_bits if b not in known_bits]

    remediation_mask = default_remediation(rec.flags)
    severity = severity_of(rec.flags)

    return DiagnosisResponse(
        agent_wallet=rec.agent_wallet,
        epoch=rec.epoch,
        score=rec.score,
        alert_tier=_tier(rec.alert_tier),
        alert_tier_code=rec.alert_tier,
        immediate_red=rec.immediate_red,
        dimensions=[
            DimensionBreakdownEntry(
                dimension=b.dimension,
                score=b.score,
                max_score=b.max_score,
                score_normalised=b.score_normalised,
                flags=b.flags,
                sub_scores=dict(b.sub_scores),
                algo_version=b.algo_version,
            )
            for b in rec.dimensions.values()
        ],
        weighted_contributions=dict(rec.weighted_contributions),
        flags=rec.flags,
        decoded_labels=[
            DecodedFlagLabel(
                name=label.name,
                bit=label.bit,
                description=label.description,
                severity=label.severity.name,
                owasp_refs=list(label.owasp_refs),
            )
            for label in decoded
        ],
        undecoded_flag_bits=undecoded,
        remediation_hints=[
            RemediationHint(name=rc.name, bit=int(rc).bit_length() - 1)
            for rc in RemediationCode
            if (int(remediation_mask) & int(rc)) == int(rc) and int(rc) != 0
        ],
        aggregate_severity=severity.name,
        confidence=rec.confidence,
        gaming_detected=rec.gaming_detected,
        gaming_drop_fraction=rec.gaming_drop_fraction,
        delta_clamped=rec.delta_clamped,
        scoring_algo_version=rec.scoring_algo_version,
        scoring_weights_version=rec.scoring_weights_version,
        scoring_schema_fingerprint=rec.scoring_schema_fingerprint,
        baseline_stats_hash=rec.baseline_stats_hash,
        computed_at=rec.computed_at,
    )


def _bit_positions(mask: int) -> list[int]:
    out: list[int] = []
    bit = 0
    remaining = mask
    while remaining:
        if remaining & 1:
            out.append(bit)
        remaining >>= 1
        bit += 1
    return out


# =============================================================================
# The factory
# =============================================================================

def create_app(
    *,
    score_repo:      ScoreRepository,
    byzantine_repo:  ByzantineRepository,
    cluster_repo:    ClusterHealthRepository,
    diagnosis_repo:  DiagnosisRepository | None = None,
    network:         str            = "localnet",
    is_production:   bool           = False,
    scoring_algo_version:    str | None = None,
    scoring_weights_version: str | None = None,
    metrics_registry: CollectorRegistry | None = None,
    # ── VULN-09: auth + rate limit ───────────────────────────────────────
    key_registry:    ApiKeyRegistry | None = None,
    rate_limiter:    SlidingWindowLimiter | None = None,
    public_rate_limit_per_minute: int = DEFAULT_PUBLIC_RATE_LIMIT_PER_MIN,
    trust_proxy:     bool = False,
    # ── DBP-4d: cert-degrading webhooks (Insured tier) ───────────────────
    webhook_registry:   WebhookRegistry  | None = None,
    webhook_dispatcher: WebhookDispatcher | None = None,
) -> FastAPI:
    """Build the FastAPI app wired to the supplied repos.

    VULN-09 wiring
    --------------
    `key_registry` is the set of API keys accepted on this process.
    Defaults to an empty registry — operational endpoints will then 401
    every request (the correct posture for an unconfigured production
    service).

    `rate_limiter` is the shared sliding-window limiter. A fresh
    in-process limiter is created if not supplied. Tests pass a fresh
    limiter per test to avoid cross-contamination.

    `public_rate_limit_per_minute` is the per-IP cap for anonymous
    traffic. `trust_proxy` controls whether the leftmost
    `X-Forwarded-For` is honoured as the client IP.
    """

    registry = metrics_registry if metrics_registry is not None else make_registry()
    metrics  = ApiMetrics(registry)
    metrics.is_production.set(1 if is_production else 0)
    metrics.schema_version.set(SCHEMA_VERSION)

    if diagnosis_repo is None:
        # An unwired diagnosis tier defaults to an empty in-memory repo —
        # the routes still respond (with 404) so a tracking client can
        # detect the surface exists. This matches the score_repo's
        # "empty repo at bring-up" posture.
        from api.diagnosis_repo import InMemoryDiagnosisRepo
        diagnosis_repo = InMemoryDiagnosisRepo()

    if key_registry is None:
        key_registry = ApiKeyRegistry()
    if rate_limiter is None:
        rate_limiter = SlidingWindowLimiter()
    if public_rate_limit_per_minute < 1:
        raise ValueError("public_rate_limit_per_minute must be >= 1")
    if webhook_registry is None:
        webhook_registry = WebhookRegistry()
    if webhook_dispatcher is None:
        webhook_dispatcher = NullDispatcher()
    degrading_tracker = CertDegradingTracker()

    app = FastAPI(
        title="Helixor V2 API",
        description="Read-side cache for Helixor agent health certificates.",
        version=__version__,
    )

    require_key = require_api_key(key_registry)

    # ── Middleware: rate limit (VULN-09) ────────────────────────────────────
    #
    # Fires BEFORE the route handler so a rejected request never touches
    # the repo. The middleware looks the API key up itself (no DI yet
    # since we are upstream of the route), and charges either the
    # per-key bucket or the per-IP bucket. Liveness + Prometheus +
    # OpenAPI docs are unmetered — those must always answer.

    @app.middleware("http")
    async def _rate_limit(request: Request, call_next):
        path = request.url.path
        if _is_unmetered(path):
            request.state.api_key = None
            return await call_next(request)

        raw_key = request.headers.get("x-api-key") or ""
        api_key = key_registry.lookup(raw_key) if raw_key else None
        request.state.api_key = api_key

        if api_key is not None:
            bucket = f"key:{api_key.key_id}"
            limit  = api_key.rate_limit_per_minute
            bucket_type = "key"
        else:
            ip = client_ip(request, trust_proxy=trust_proxy)
            bucket = f"ip:{ip}"
            limit  = public_rate_limit_per_minute
            bucket_type = "ip"

        decision = rate_limiter.check(bucket, limit)
        if not decision.allowed:
            metrics.rate_limit_rejections_total.labels(bucket_type).inc()
            # Round up so Retry-After is never a misleading 0.
            retry_after = max(1, int(decision.retry_after_s) + 1)
            return JSONResponse(
                status_code=429,
                content=ErrorResponse(
                    error="too_many_requests",
                    detail=(
                        f"rate limit {limit}/min exceeded; "
                        f"retry in ~{retry_after}s"
                    ),
                ).model_dump(),
                headers={
                    "Retry-After":          str(retry_after),
                    "X-RateLimit-Limit":    str(limit),
                    "X-RateLimit-Remaining": "0",
                    "Cache-Control":        META_CACHE_CONTROL,
                },
            )

        response = await call_next(request)
        response.headers.setdefault("X-RateLimit-Limit",     str(decision.limit))
        response.headers.setdefault("X-RateLimit-Remaining", str(decision.remaining))
        return response

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
        # VULN-09: count 401s on operational endpoints. The route
        # template (not the literal path) keeps label cardinality bounded.
        if response.status_code == 401:
            metrics.auth_rejections_total.labels(route_template).inc()
        # DBP-4: per-partner safe-reader share. Only record if (a) the
        # call carried a valid partner-bound API key, (b) the route is
        # one of the score-read endpoints we classify, AND (c) the
        # response was a success (2xx). A 4xx/5xx is a malformed call
        # not a signal of how the partner reads scores.
        api_key = getattr(request.state, "api_key", None)
        if (
            api_key is not None
            and api_key.partner_wallet is not None
            and 200 <= response.status_code < 300
        ):
            surface = _surface_for_route(route_template)
            if surface is not None:
                metrics.safe_reader_share_total.labels(
                    api_key.partner_wallet, surface,
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
    #
    # Score reads carry SCORE_CACHE_CONTROL so an upstream CDN can serve
    # them — the audit's mitigation #2. Operational endpoints carry
    # OPERATIONAL_CACHE_CONTROL and require a valid API key — the
    # audit's mitigation #3. Meta endpoints (`/version`, `/health`,
    # `/metrics`) carry META_CACHE_CONTROL.

    @app.get("/agents/{wallet}/health", response_model=HealthResponse)
    def agent_health(wallet: str, response: Response) -> HealthResponse:
        wallet = validate_wallet(wallet)
        rec = score_repo.latest_score(wallet)
        if rec is None:
            raise HTTPException(404, f"no score recorded for {wallet}")
        response.headers["Cache-Control"] = SCORE_CACHE_CONTROL
        return _to_health(rec)

    @app.get("/agents/{wallet}/health/{epoch}", response_model=HealthResponse)
    def agent_health_at_epoch(
        wallet: str, epoch: int, response: Response,
    ) -> HealthResponse:
        wallet = validate_wallet(wallet)
        if epoch < 1:
            raise HTTPException(400, "epoch must be >= 1")
        rec = score_repo.score_at_epoch(wallet, epoch)
        if rec is None:
            raise HTTPException(404, f"no score for {wallet} at epoch {epoch}")
        response.headers["Cache-Control"] = SCORE_CACHE_CONTROL
        return _to_health(rec)

    @app.get("/agents/{wallet}/diagnosis", response_model=DiagnosisResponse)
    def agent_diagnosis(wallet: str, response: Response) -> DiagnosisResponse:
        """Day-34 Phase-1: structured diagnosis for the latest epoch.

        The response carries `attestation: "off_chain_v1"` — the data
        is faithful to the oracle's epoch_runner output but is not
        threshold-signed (Phase-2 cert v2 will be). A consumer that
        builds its own audit chain MUST switch on the attestation tag.
        """
        wallet = validate_wallet(wallet)
        rec = diagnosis_repo.latest_diagnosis(wallet)
        if rec is None:
            raise HTTPException(404, f"no diagnosis recorded for {wallet}")
        # Off-chain diagnosis IS operational data: it exposes the raw
        # u32 flag bitmask + the per-dimension breakdown the score-only
        # endpoint deliberately obfuscates. We do not let intermediaries
        # cache it, and we do not let the CDN serve a stale copy past
        # the next epoch advance.
        response.headers["Cache-Control"] = OPERATIONAL_CACHE_CONTROL
        return _to_diagnosis(rec)

    @app.get(
        "/agents/{wallet}/diagnosis/{epoch}", response_model=DiagnosisResponse,
    )
    def agent_diagnosis_at_epoch(
        wallet: str, epoch: int, response: Response,
    ) -> DiagnosisResponse:
        wallet = validate_wallet(wallet)
        if epoch < 1:
            raise HTTPException(400, "epoch must be >= 1")
        rec = diagnosis_repo.diagnosis_at_epoch(wallet, epoch)
        if rec is None:
            raise HTTPException(
                404, f"no diagnosis for {wallet} at epoch {epoch}",
            )
        response.headers["Cache-Control"] = OPERATIONAL_CACHE_CONTROL
        return _to_diagnosis(rec)

    @app.get("/agents/{wallet}/safe_score", response_model=SafeScoreResponse)
    def agent_safe_score(
        wallet: str, request: Request, response: Response,
    ) -> SafeScoreResponse:
        """VULN-23 guard-railed score read.

        The DeFi-protocol-friendly endpoint: returns the agent's current
        score ONLY IF the cert is fresh (<= 48h) and the score has not
        swung > 200 points across the rolling 3-epoch window. Otherwise
        returns a structured rejection with a machine-readable `reason`.

        Status code is always 200 — the rejection is in the body so a
        thin client doesn't need to distinguish HTTP failure from a
        guard-rail trip.

        DBP-4d cert-degrading webhook
        -----------------------------
        On an OK result, if the caller is a Verified-Integrator (their
        key carries a `partner_wallet`) AND that partner has a webhook
        registered AND the cert's age is in the [75%, 100%) window of
        CERT_MAX_AGE_SECONDS, we fire a `cert.degrading` webhook
        exactly once per (partner, agent, epoch). The dispatcher is
        non-blocking — the response goes back to the caller without
        waiting for the POST to complete.
        """
        wallet = validate_wallet(wallet)
        result = compute_safe_score(score_repo, wallet)
        # Do not CDN-cache safe-score reads: the freshness boundary moves
        # second-by-second, and a cached "ok" past its `issued_at + 48h`
        # window would silently defeat the guard.
        response.headers["Cache-Control"] = OPERATIONAL_CACHE_CONTROL
        if isinstance(result, SafeScoreOk):
            _maybe_fire_cert_degrading_webhook(
                request=request, wallet=wallet, ok=result,
                webhook_registry=webhook_registry,
                dispatcher=webhook_dispatcher,
                tracker=degrading_tracker,
            )
            return SafeScoreResponse(
                agent_wallet=wallet,
                ok=True,
                score=result.score,
                alert_tier=result.alert_tier,
                alert_tier_code=result.alert_tier_code,
                epoch=result.epoch,
                issued_at_unix=result.issued_at_unix,
                velocity_window=SafeScoreVelocityWindow(
                    min_score=result.velocity_min,
                    max_score=result.velocity_max,
                    epochs=list(result.window_epochs),
                ),
            )
        return SafeScoreResponse(
            agent_wallet=wallet,
            ok=False,
            reason=result.reason,
            detail=result.detail,
        )

    @app.get("/agents/{wallet}/history", response_model=HistoryResponse)
    def agent_history(
        wallet: str,
        response: Response,
        from_epoch: int | None = None,
        to_epoch:   int | None = None,
        limit:      int = 100,
    ) -> HistoryResponse:
        wallet = validate_wallet(wallet)
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
        response.headers["Cache-Control"] = SCORE_CACHE_CONTROL
        return HistoryResponse(
            agent_wallet=wallet,
            entries=[_to_history_entry(r) for r in records],
            from_epoch=from_epoch, to_epoch=to_epoch, limit=limit,
        )

    @app.get(
        "/byzantine/recent", response_model=ByzantineRecentResponse,
        dependencies=[Depends(require_key)],
    )
    def byzantine_recent(
        response: Response,
        since_epoch: int | None = None, limit: int = 100,
    ) -> ByzantineRecentResponse:
        if limit < 1 or limit > 1000:
            raise HTTPException(400, "limit must be 1..1000")
        flags = byzantine_repo.recent_flags(
            since_epoch=since_epoch, limit=limit,
        )
        response.headers["Cache-Control"] = OPERATIONAL_CACHE_CONTROL
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

    @app.get(
        "/byzantine/strikes", response_model=StrikeSummaryResponse,
        dependencies=[Depends(require_key)],
    )
    def byzantine_strikes(response: Response) -> StrikeSummaryResponse:
        rows = byzantine_repo.strike_summary()
        response.headers["Cache-Control"] = OPERATIONAL_CACHE_CONTROL
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

    @app.get(
        "/byzantine/per_node", response_model=PerNodeRevealsResponse,
        dependencies=[Depends(require_key)],
    )
    def byzantine_per_node(
        epoch: int, agent: str, response: Response,
    ) -> PerNodeRevealsResponse:
        agent = validate_wallet(agent)
        if epoch < 1:
            raise HTTPException(400, "epoch must be >= 1")
        reveals = byzantine_repo.per_node_reveals(epoch=epoch, agent_wallet=agent)
        response.headers["Cache-Control"] = OPERATIONAL_CACHE_CONTROL
        return PerNodeRevealsResponse(
            epoch=epoch, agent=agent,
            reveals=[
                PerNodeRevealEntry(node=r.node_id, score=r.score)
                for r in reveals
            ],
        )

    @app.get(
        "/challenges", response_model=ChallengesResponse,
        dependencies=[Depends(require_key)],
    )
    def challenges(node: str, response: Response) -> ChallengesResponse:
        node = validate_wallet(node)
        rows = byzantine_repo.challenges_for(node)
        response.headers["Cache-Control"] = OPERATIONAL_CACHE_CONTROL
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

    @app.get(
        "/health/cluster", response_model=ClusterHealthResponse,
        dependencies=[Depends(require_key)],
    )
    def cluster_health(
        response: Response, limit: int = 10,
    ) -> ClusterHealthResponse:
        if limit < 1 or limit > 1000:
            raise HTTPException(400, "limit must be 1..1000")
        response.headers["Cache-Control"] = OPERATIONAL_CACHE_CONTROL
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

    @app.get(
        "/integrations/leaderboard",
        response_model=IntegrationLeaderboardResponse,
    )
    def integrations_leaderboard(
        response: Response,
    ) -> IntegrationLeaderboardResponse:
        """DBP-4c — public Verified-Integrator safe-reader leaderboard.

        Reads the `safe_reader_share_total{partner_wallet, surface}`
        counter, aggregates by `partner_wallet`, and returns a ranked
        list. Partners are sorted by `safe_share` desc with a
        `total_calls` tiebreak; partners with no observed calls appear
        last in `partner_wallet` order.

        The endpoint is intentionally PUBLIC (no API key required) —
        the leaderboard is a misuse-deterrent surface. A partner who
        flips back to raw-only reads should see their rank drop
        immediately, and any consumer should be able to read the
        ranking before deciding whether to trust that partner's certs.
        """
        response.headers["Cache-Control"] = SCORE_CACHE_CONTROL
        # Aggregate counter samples by partner_wallet. We walk every key
        # in the registry so a partner who's registered but hasn't yet
        # called the API still appears in the response — with zero
        # counts and safe_share = None. This makes the response
        # deterministic vs the registry rather than vs the counter state.
        partner_wallets: list[str] = sorted({
            k.partner_wallet
            for k in key_registry._keys
            if k.partner_wallet is not None
        })
        counter = metrics.safe_reader_share_total
        rows: list[IntegrationLeaderboardEntry] = []
        for pw in partner_wallets:
            safe = counter.labels(pw, "safe")._value.get()
            raw  = counter.labels(pw, "raw")._value.get()
            total = int(safe + raw)
            share = (safe / total) if total > 0 else None
            rows.append(IntegrationLeaderboardEntry(
                partner_wallet=pw,
                safe_calls=int(safe),
                raw_calls=int(raw),
                total_calls=total,
                safe_share=share,
            ))
        # Sort: rows WITH observed traffic first (by safe_share desc,
        # then total_calls desc), then rows with no traffic by wallet.
        observed = [r for r in rows if r.total_calls > 0]
        idle     = [r for r in rows if r.total_calls == 0]
        observed.sort(
            key=lambda r: (-(r.safe_share or 0.0), -r.total_calls,
                           r.partner_wallet),
        )
        idle.sort(key=lambda r: r.partner_wallet)
        return IntegrationLeaderboardResponse(ranking=observed + idle)

    @app.get("/version", response_model=VersionResponse)
    def version(response: Response) -> VersionResponse:
        response.headers["Cache-Control"] = META_CACHE_CONTROL
        return VersionResponse(
            api_version=__version__,
            scoring_algo_version=scoring_algo_version,
            scoring_weights_version=scoring_weights_version,
            network=network,
            network_is_production=is_production,
        )

    @app.get("/health")
    def health_liveness(response: Response) -> dict:
        # Standard k8s/systemd liveness — fast, no I/O.
        response.headers["Cache-Control"] = META_CACHE_CONTROL
        return {"status": "ok", "schema_version": SCHEMA_VERSION}

    @app.get("/metrics")
    def metrics_endpoint() -> Response:
        data, content_type = render_metrics(registry)
        return Response(
            content=data, media_type=content_type,
            headers={"Cache-Control": META_CACHE_CONTROL},
        )

    # Hang the metrics + registry off the app for tests to inspect.
    # VULN-09: also expose the key registry + limiter so tests can build
    # auth flows without re-importing. DBP-4d: also expose the webhook
    # registry + dispatcher + dedupe tracker.
    app.state.metrics = metrics
    app.state.registry = registry
    app.state.key_registry = key_registry
    app.state.rate_limiter = rate_limiter
    app.state.public_rate_limit_per_minute = public_rate_limit_per_minute
    app.state.trust_proxy = trust_proxy
    app.state.webhook_registry = webhook_registry
    app.state.webhook_dispatcher = webhook_dispatcher
    app.state.degrading_tracker = degrading_tracker
    app.state.diagnosis_repo = diagnosis_repo
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


def _maybe_fire_cert_degrading_webhook(
    *,
    request:           Request,
    wallet:            str,
    ok:                SafeScoreOk,
    webhook_registry:  WebhookRegistry,
    dispatcher:        WebhookDispatcher,
    tracker:           CertDegradingTracker,
) -> None:
    """DBP-4d trigger. Fires a `cert.degrading` webhook when:

      (1) the caller's API key carries a `partner_wallet`,
      (2) that partner has a webhook registered,
      (3) the cert's age is in the [degrading_threshold, max_age) window,
      (4) this is the FIRST observation of (partner, agent, epoch) in
          this process (the tracker dedupes).

    Anything else (no key, basic-tier key, no webhook, cert is fresh,
    or cert is past expiry — which can't actually happen because
    compute_safe_score would already have refused) is a silent no-op.
    """
    api_key: ApiKey | None = getattr(request.state, "api_key", None)
    if api_key is None or api_key.partner_wallet is None:
        return
    hook = webhook_registry.get(api_key.partner_wallet)
    if hook is None:
        return

    now_unix = int(time.time())
    age_seconds = now_unix - ok.issued_at_unix
    threshold = degrading_threshold_seconds(CERT_MAX_AGE_SECONDS)
    if age_seconds < threshold:
        return
    # compute_safe_score already enforces age < CERT_MAX_AGE_SECONDS,
    # but we guard defensively in case constants drift.
    if age_seconds >= CERT_MAX_AGE_SECONDS:
        return

    if not tracker.should_fire(
        partner_wallet=api_key.partner_wallet,
        agent_wallet=wallet,
        epoch=ok.epoch,
    ):
        return

    payload = CertDegradingPayload(
        schema_version=WEBHOOK_SCHEMA_VERSION,
        event=EVENT_CERT_DEGRADING,
        partner_wallet=api_key.partner_wallet,
        agent_wallet=wallet,
        epoch=ok.epoch,
        issued_at_unix=ok.issued_at_unix,
        cert_age_seconds=age_seconds,
        threshold_seconds=threshold,
        cert_max_age_seconds=CERT_MAX_AGE_SECONDS,
        sent_at_unix=now_unix,
    )
    dispatcher.dispatch(hook=hook, payload=payload)


def _default_error_name(status: int) -> str:
    return {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        429: "too_many_requests",
        500: "internal_error",
    }.get(status, f"http_{status}")
