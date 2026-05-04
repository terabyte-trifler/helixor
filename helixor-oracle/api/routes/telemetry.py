"""
api/routes/telemetry.py — plugin telemetry beacon endpoint.

Plugins POST events here. We dedup by beacon_id, attribute to operator if
they sent an API key, and persist into plugin_telemetry.

CRITICAL: this endpoint NEVER stores message content. Only metadata —
event type, score, action name, decision reason. If a future PR adds a
field, audit it against the schema before merging.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from typing import Literal

import asyncpg
import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from api.auth import extract_bearer_token, hash_api_key
from api.rate_limit import rate_limit_dep
from api.validation import validate_agent_wallet
from indexer import db

log = structlog.get_logger(__name__)
router = APIRouter()


# =============================================================================
# Pydantic models
# =============================================================================

EventType = Literal[
    "plugin_initialized",
    "agent_score_fetched",
    "action_allowed",
    "action_blocked",
    "gate_error",
    "score_changed",
    "anomaly_detected",
    "agent_deactivated",
    "plugin_shutdown",
]


class TelemetryBeacon(BaseModel):
    """One telemetry event from a plugin instance."""

    event_type:        EventType
    plugin_version:    str = Field(..., max_length=32)
    elizaos_version:   str | None = Field(None, max_length=32)
    node_version:      str | None = Field(None, max_length=32)

    agent_wallet:      str | None = Field(None, max_length=44)
    character_name:    str | None = Field(None, max_length=128)

    score:             int | None = Field(None, ge=0, le=1000)
    alert_level:       Literal["GREEN", "YELLOW", "RED"] | None = None
    block_reason:      str | None = Field(None, max_length=64)
    action_name:       str | None = Field(None, max_length=64)
    error_message:     str | None = Field(None, max_length=500)

    extra:             dict = Field(default_factory=dict)

    beacon_id:         str = Field(..., min_length=8, max_length=64)

    @field_validator("agent_wallet")
    @classmethod
    def _validate_pk(cls, v):
        if v is None:
            return None
        # Reuse validation; raises HTTPException(400) on bad input — but we
        # need to propagate that through Pydantic, so re-raise as ValueError
        try:
            validate_agent_wallet(v)
        except HTTPException as e:
            raise ValueError(e.detail.get("error", "invalid pubkey"))
        return v

    @field_validator("extra")
    @classmethod
    def _bound_extra(cls, v: dict) -> dict:
        """Cap extra payload size — prevents abuse."""
        if len(json.dumps(v)) > 2048:
            raise ValueError("extra payload exceeds 2048 bytes")
        # Reject keys that look like message content
        forbidden = {"text", "message", "content", "prompt", "user_input", "user_message"}
        for k in v.keys():
            if k.lower() in forbidden:
                raise ValueError(
                    f"telemetry must NOT include message content (forbidden key: {k})"
                )
        return v


class TelemetryAck(BaseModel):
    accepted:   bool
    beacon_id:  str
    deduped:    bool                 # true if we'd already seen this beacon_id
    request_id: str


# =============================================================================
# Operator resolution from API key
# =============================================================================

def _safe_source_ip(request: Request) -> str | None:
    """Return a DB-safe IP string, or None for non-IP clients like TestClient."""
    host = request.client.host if request.client else None
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


async def _resolve_operator(
    conn:    asyncpg.Connection,
    api_key: str | None,
) -> int | None:
    """Return operator_id if api_key matches a registered operator, else None."""
    if not api_key:
        return None

    key_hash = hash_api_key(api_key)
    row = await conn.fetchrow(
        """
        UPDATE operators
        SET last_seen_at = NOW()
        WHERE api_key_hash = $1 AND enabled = TRUE
        RETURNING id
        """,
        key_hash,
    )
    return row["id"] if row else None


# =============================================================================
# Endpoint
# =============================================================================

@router.post(
    "/telemetry/beacon",
    response_model=TelemetryAck,
    dependencies=[Depends(rate_limit_dep)],
    status_code=status.HTTP_202_ACCEPTED,
    summary="Plugin lifecycle/decision beacon (metadata only, no content)",
)
async def receive_beacon(
    beacon:        TelemetryBeacon,
    request:       Request,
    authorization: str | None = Header(None, alias="Authorization"),
) -> TelemetryAck:
    """
    Accept a plugin telemetry beacon. Idempotent — repeat calls with the
    same beacon_id return deduped=True without inserting again.

    Authorization header is optional. If present and matches a registered
    operator, the beacon is attributed to them.
    """
    pool = await db.get_pool()

    api_key = extract_bearer_token(authorization)

    request_id = request.headers.get("x-request-id", "unknown")

    async with pool.acquire() as conn:
        operator_id = await _resolve_operator(conn, api_key)

        # Dedup: try insert; if beacon_id already exists, return deduped=True
        try:
            await conn.execute(
                """
                INSERT INTO plugin_telemetry (
                    operator_id, event_type, plugin_version, elizaos_version,
                    node_version, agent_wallet, character_name,
                    score, alert_level, block_reason, action_name, error_message,
                    extra, source_ip, user_agent, beacon_id
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7,
                    $8, $9, $10, $11, $12,
                    $13::jsonb, $14, $15, $16
                )
                """,
                operator_id, beacon.event_type, beacon.plugin_version,
                beacon.elizaos_version, beacon.node_version,
                beacon.agent_wallet, beacon.character_name,
                beacon.score, beacon.alert_level, beacon.block_reason,
                beacon.action_name, beacon.error_message,
                json.dumps(beacon.extra),
                _safe_source_ip(request),
                request.headers.get("user-agent"),
                beacon.beacon_id,
            )
            deduped = False
        except asyncpg.UniqueViolationError:
            deduped = True

        # Update operator_integrations (best-effort — failures don't fail the beacon)
        if operator_id and beacon.agent_wallet and not deduped:
            try:
                inc_blocks = 1 if beacon.event_type == "action_blocked" else 0
                inc_allows = 1 if beacon.event_type == "action_allowed" else 0
                await conn.execute(
                    """
                    INSERT INTO operator_integrations (
                        operator_id, agent_wallet, character_name, plugin_version,
                        first_seen_at, last_seen_at, blocks_count, allows_count
                    ) VALUES ($1, $2, $3, $4, NOW(), NOW(), $5, $6)
                    ON CONFLICT (operator_id, agent_wallet) DO UPDATE SET
                        last_seen_at   = NOW(),
                        plugin_version = EXCLUDED.plugin_version,
                        character_name = COALESCE(EXCLUDED.character_name,
                                                   operator_integrations.character_name),
                        blocks_count   = operator_integrations.blocks_count + $5,
                        allows_count   = operator_integrations.allows_count + $6
                    """,
                    operator_id, beacon.agent_wallet, beacon.character_name,
                    beacon.plugin_version, inc_blocks, inc_allows,
                )
            except Exception as e:
                log.warning("integration_update_failed", error=str(e))

    log.info(
        "telemetry_beacon",
        beacon_event=beacon.event_type, operator_id=operator_id,
        plugin_version=beacon.plugin_version,
        agent=(beacon.agent_wallet or "")[:12] + "..." if beacon.agent_wallet else None,
        score=beacon.score, alert=beacon.alert_level,
        deduped=deduped,
    )

    return TelemetryAck(
        accepted=True, beacon_id=beacon.beacon_id, deduped=deduped,
        request_id=request_id,
    )


# =============================================================================
# Operator-facing confirmation endpoint
# =============================================================================

class IntegrationSummary(BaseModel):
    operator_id:      int
    organization:     str | None
    contact_email:    str | None
    discord_handle:   str | None
    tier:             str
    integrations:     list[dict]
    plugin_initialized_count: int
    blocks_24h:       int
    allows_24h:       int


@router.get(
    "/telemetry/whoami",
    response_model=IntegrationSummary,
    dependencies=[Depends(rate_limit_dep)],
    summary="Confirm plugin installation + see operator's recent activity",
)
async def whoami(
    authorization: str | None = Header(None, alias="Authorization"),
) -> IntegrationSummary:
    """
    Operator hits this endpoint with their API key. Returns confirmation +
    recent activity. Used by the `npx @elizaos/plugin-helixor status` CLI.
    """
    api_key = extract_bearer_token(authorization)
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "API key required for /telemetry/whoami",
                    "code": "AUTH_REQUIRED"},
        )

    pool     = await db.get_pool()

    async with pool.acquire() as conn:
        op = await conn.fetchrow(
            "SELECT * FROM operators WHERE api_key_hash = $1 AND enabled = TRUE",
            hash_api_key(api_key),
        )
        if not op:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "API key not recognized", "code": "INVALID_API_KEY"},
            )

        integrations = await conn.fetch(
            """
            SELECT agent_wallet, character_name, plugin_version,
                   first_seen_at, last_seen_at,
                   blocks_count, allows_count
            FROM operator_integrations
            WHERE operator_id = $1
            ORDER BY last_seen_at DESC
            """,
            op["id"],
        )
        init_count = await conn.fetchval(
            """
            SELECT COUNT(*) FROM plugin_telemetry
            WHERE operator_id = $1
              AND event_type = 'plugin_initialized'
              AND received_at >= NOW() - INTERVAL '7 days'
            """,
            op["id"],
        )
        blocks_24h = await conn.fetchval(
            """
            SELECT COUNT(*) FROM plugin_telemetry
            WHERE operator_id = $1
              AND event_type = 'action_blocked'
              AND received_at >= NOW() - INTERVAL '24 hours'
            """,
            op["id"],
        )
        allows_24h = await conn.fetchval(
            """
            SELECT COUNT(*) FROM plugin_telemetry
            WHERE operator_id = $1
              AND event_type = 'action_allowed'
              AND received_at >= NOW() - INTERVAL '24 hours'
            """,
            op["id"],
        )

    return IntegrationSummary(
        operator_id    = op["id"],
        organization   = op["organization"],
        contact_email  = op["contact_email"],
        discord_handle = op["discord_handle"],
        tier           = op["tier"],
        integrations   = [dict(r) for r in integrations],
        plugin_initialized_count = init_count or 0,
        blocks_24h     = blocks_24h or 0,
        allows_24h     = allows_24h or 0,
    )
