"""
api/routes/score.py — score endpoints.

GET /score/{agent_wallet}      — fetch one agent's current score
GET /agents                    — list all active agents (paginated)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.rate_limit import rate_limit_dep
from api.schemas import AgentListResponse, ErrorResponse, ScoreResponse
from api.service import score_service
from api.validation import validate_agent_wallet
from indexer import db

router = APIRouter()


@router.get(
    "/score/{agent_wallet}",
    response_model=ScoreResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid agent_wallet"},
        404: {"model": ErrorResponse, "description": "Agent not registered"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
    },
    dependencies=[Depends(rate_limit_dep)],
    summary="Get current trust score for an agent",
)
async def get_score(
    agent_wallet:  str  = Depends(validate_agent_wallet),
    force_refresh: bool = Query(False, description="Bypass cache for this call"),
) -> ScoreResponse:
    """
    Returns the latest trust score for a registered agent.

    Response sources (in order of preference):
      • cache  (60s TTL)
      • PostgreSQL agent_scores
      • Provisional response (registered, no score yet)

    Returns 404 if agent is not registered.
    """
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        result = await score_service.get_score(
            conn, agent_wallet, force_refresh=force_refresh,
        )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "Agent not registered with Helixor",
                "code":  "AGENT_NOT_FOUND",
            },
        )

    return result


@router.get(
    "/agents",
    response_model=AgentListResponse,
    dependencies=[Depends(rate_limit_dep)],
    summary="List active agents (paginated)",
)
async def list_agents(
    limit:  int = Query(50, ge=1, le=500),
    offset: int = Query(0,  ge=0),
) -> AgentListResponse:
    """List active agents with their latest scores."""
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        items, total = await score_service.list_agents(
            conn, limit=limit, offset=offset,
        )

    return AgentListResponse(items=items, total=total, limit=limit)
