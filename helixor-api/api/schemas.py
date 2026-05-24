"""
api/schemas.py — the JSON contract.

Every HTTP response in helixor-api is one of these Pydantic models. The
shape here IS the wire format — clients depend on it. Adding fields is
safe (additive); renaming or removing is a breaking change and goes
through the API versioning policy in launch/RUNBOOK_api_versioning.md.

Each model carries an `_v` field with the schema version so an older
client can detect a forward-incompatible response.

A NOTE ON THE HEALTH ENDPOINT
-----------------------------
The wire shape for `GET /agents/{wallet}/health` mirrors the on-chain
HealthCertificate fields plus `signer_count`. This is the same shape
the SDK's `EpochScore` exposes (helixor-sdk/src/types.ts) — clients can
use either path with identical response decoding.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


SCHEMA_VERSION = 1


# =============================================================================
# Health endpoint
# =============================================================================

class HealthResponse(BaseModel):
    """`GET /agents/{wallet}/health` — current score for an agent."""
    schema_version: int = Field(SCHEMA_VERSION, alias="_v")
    agent_wallet:   str
    epoch:          int
    score:          int          # 0..1000
    alert_tier:     str          # "GREEN" | "YELLOW" | "RED"
    alert_tier_code: int         # 0 | 1 | 2 (matches on-chain enum)
    flags:          int          # u32 aggregated detection flags
    immediate_red:  bool
    signer_count:   int          # how many cluster keys signed this cert
    computed_at:    datetime

    model_config = ConfigDict(populate_by_name=True)


class HistoryEntry(BaseModel):
    epoch:        int
    score:        int
    alert_tier:   str
    alert_tier_code: int
    immediate_red: bool
    signer_count: int
    computed_at:  datetime


class HistoryResponse(BaseModel):
    """`GET /agents/{wallet}/history` — paged epoch history."""
    schema_version: int = Field(SCHEMA_VERSION, alias="_v")
    agent_wallet:   str
    entries:        list[HistoryEntry]
    from_epoch:     int | None
    to_epoch:       int | None
    limit:          int


# =============================================================================
# Byzantine — what runbooks query
# =============================================================================

class ByzantineFlagEntry(BaseModel):
    node:           str
    epoch:          int
    subject_agent:  str
    accused_score:  int
    cluster_median: int
    deviation:      float


class ByzantineRecentResponse(BaseModel):
    schema_version: int = Field(SCHEMA_VERSION, alias="_v")
    flags:          list[ByzantineFlagEntry]
    since_epoch:    int | None


class StrikeEntry(BaseModel):
    strikes:        int
    flagged_epochs: list[int]
    challenged:     bool


class StrikeSummaryResponse(BaseModel):
    """node_id -> StrikeEntry. The runbook uses this for grep."""
    schema_version: int = Field(SCHEMA_VERSION, alias="_v")
    summary:        dict[str, StrikeEntry]


class PerNodeRevealEntry(BaseModel):
    node:  str
    score: int


class PerNodeRevealsResponse(BaseModel):
    schema_version: int = Field(SCHEMA_VERSION, alias="_v")
    epoch:          int
    agent:          str
    reveals:        list[PerNodeRevealEntry]


# =============================================================================
# Challenges — Day 21
# =============================================================================

class ChallengeEntry(BaseModel):
    challenge_index: int
    accused_node:    str
    proof_type:      int        # 0 = ConflictingScores
    subject_epoch:   int
    subject_agent:   str
    accused_score:   int
    cluster_median:  int
    evidence_hash:   str
    status:          str
    filed_at:        int


class ChallengesResponse(BaseModel):
    schema_version: int = Field(SCHEMA_VERSION, alias="_v")
    accused_node:   str
    challenges:     list[ChallengeEntry]


# =============================================================================
# Cluster health — node_down.md
# =============================================================================

class HeartbeatEntry(BaseModel):
    node:           str
    last_seen_unix: int
    epoch:          int


class EpochSummaryEntry(BaseModel):
    epoch:            int
    submitted_count:  int
    agent_count:      int
    verified_nodes:   list[str]
    byzantine_nodes:  list[str]
    unreachable_nodes: list[str]
    elapsed_seconds:  float
    computed_at:      datetime


class ClusterHealthResponse(BaseModel):
    schema_version: int = Field(SCHEMA_VERSION, alias="_v")
    heartbeats:     list[HeartbeatEntry]
    recent_epochs:  list[EpochSummaryEntry]


# =============================================================================
# Version — runbook uses this for cross-node version comparison
# =============================================================================

class VersionResponse(BaseModel):
    schema_version:        int = Field(SCHEMA_VERSION, alias="_v")
    api_version:           str
    scoring_algo_version:  str | None
    scoring_weights_version: str | None
    network:               str           # localnet / devnet / mainnet-beta
    network_is_production: bool


# =============================================================================
# Errors
# =============================================================================

class ErrorResponse(BaseModel):
    error:   str
    detail:  str | None = None
