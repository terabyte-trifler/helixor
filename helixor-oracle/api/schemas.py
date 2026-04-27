"""
api/schemas.py — pydantic response models for the Helixor REST API.

All response shapes live here so the OpenAPI schema matches what we emit.
Field names use snake_case (HTTP convention); SDK normalizes to camelCase.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

AlertLevel  = Literal["GREEN", "YELLOW", "RED"]
ScoreSource = Literal["live", "stale", "provisional", "deactivated"]


class ScoreBreakdown(BaseModel):
    """Per-component breakdown returned alongside the score."""
    success_rate_score: int = Field(ge=0, le=500)
    consistency_score:  int = Field(ge=0, le=300)
    stability_score:    int = Field(ge=0, le=200)
    raw_score:          int = Field(ge=0, le=1000)
    guard_rail_applied: bool


class ScoreResponse(BaseModel):
    """The primary GET /score/{agent} payload."""
    agent_wallet:   str
    score:          int       = Field(ge=0, le=1000)
    alert:          AlertLevel
    source:         ScoreSource
    success_rate:   float     = Field(ge=0.0, le=100.0,
                                       description="Percentage 0.0-100.0")
    anomaly_flag:   bool
    updated_at:     int       = Field(description="Unix epoch seconds, 0 if never scored")
    is_fresh:       bool      = Field(description="False if cert > 48h old")

    # Versions + breakdown for transparency
    breakdown:               ScoreBreakdown | None = None
    scoring_algo_version:    int | None = None
    weights_version:         int | None = None
    baseline_hash_prefix:    str | None = Field(
        None, description="First 16 bytes of baseline hash, hex-encoded",
    )

    # Operational meta
    served_at:      int       = Field(description="Server time when this response was built")
    cached:         bool      = Field(description="True if served from cache, false if fresh")


class AgentSummary(BaseModel):
    """Short item used by the GET /agents listing."""
    agent_wallet: str
    score:        int | None
    alert:        AlertLevel | None
    is_fresh:     bool | None
    updated_at:   int | None


class AgentListResponse(BaseModel):
    """GET /agents listing response."""
    items:  list[AgentSummary]
    total:  int
    limit:  int
    cursor: str | None = None       # Day 9+ pagination


class StatusResponse(BaseModel):
    """GET /status — operational health."""
    status:        Literal["ok", "degraded"]
    version:       str
    uptime_seconds: int
    cache_size:    int
    db_reachable:  bool
    rpc_reachable: bool


class ErrorResponse(BaseModel):
    """Standard error envelope. Never leaks stack traces or internal details."""
    error:      str
    code:       str
    request_id: str
