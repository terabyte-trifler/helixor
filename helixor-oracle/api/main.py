"""
api/main.py — FastAPI app for the Helixor REST API.

Run with:
    uvicorn api.main:app --host 0.0.0.0 --port 8001 --workers 1

Why port 8001 (not 8000): Day 4's webhook receiver uses 8000. Both run
side-by-side in production.

Why workers=1: each worker holds its own asyncpg pool + cache. Scale by
adding containers, not workers.
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routes import score, status
from indexer import db

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Configure logging + DB pool around the app's lifetime."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
    )
    log.info("api_starting", version="0.8.0")
    created_pool = db._pool is None
    await db.init_pool()
    log.info("api_ready")
    try:
        yield
    finally:
        log.info("api_shutting_down")
        if created_pool:
            await db.close_pool()


app = FastAPI(
    title="Helixor API",
    description="Trust scoring for AI agents on Solana.",
    version="0.8.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allow browser apps to call us. Tighten origins in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # TODO: restrict to known consumers in prod
    allow_credentials=False,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
    max_age=3600,
)


# ─────────────────────────────────────────────────────────────────────────────
# Request ID + timing middleware
# ─────────────────────────────────────────────────────────────────────────────
@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())[:8]
    structlog.contextvars.bind_contextvars(request_id=request_id, path=request.url.path)

    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        log.exception("unhandled_exception", error=str(exc))
        return JSONResponse(
            status_code=500,
            content={
                "error":      "Internal server error",
                "code":       "INTERNAL_ERROR",
                "request_id": request_id,
            },
            headers={"X-Request-ID": request_id},
        )

    duration_ms = int((time.perf_counter() - started) * 1000)
    response.headers["X-Request-ID"]      = request_id
    response.headers["X-Response-Time"]   = f"{duration_ms}ms"

    log.info(
        "http_request",
        method=request.method,
        status_code=response.status_code,
        duration_ms=duration_ms,
    )
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Centralized error envelope — never leak internals
# ─────────────────────────────────────────────────────────────────────────────
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    request_id = structlog.contextvars.get_contextvars().get("request_id", "unknown")

    # Allow detail to be a dict (we use this for structured errors)
    if isinstance(exc.detail, dict):
        body = {**exc.detail, "request_id": request_id}
    else:
        body = {"error": str(exc.detail), "code": "ERROR", "request_id": request_id}

    return JSONResponse(
        status_code=exc.status_code,
        content=body,
        headers={"X-Request-ID": request_id, **(exc.headers or {})},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────
app.include_router(score.router,  tags=["score"])
app.include_router(status.router, tags=["operational"])


@app.get("/", include_in_schema=False)
async def root():
    return {
        "name":    "Helixor API",
        "version": "0.8.0",
        "docs":    "/docs",
    }
