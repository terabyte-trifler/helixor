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
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


SCHEMA_VERSION = 1

# Phase-1 diagnosis attestation tag. Day-34 surfaces a non-threshold-
# attested diagnosis, so we mark every response with this literal — the
# consumer can switch on it. Phase-2 lifts the same fields into the
# threshold-signed cert v2, which will mark them `"cert_v2"`.
DIAGNOSIS_ATTESTATION_OFF_CHAIN_V1: Literal["off_chain_v1"] = "off_chain_v1"


# =============================================================================
# Health endpoint
# =============================================================================

class HealthResponse(BaseModel):
    """`GET /agents/{wallet}/health` — current score for an agent.

    VULN-24 NOTE on flag exposure
    -----------------------------
    The raw `flags` bitmask is NOT exposed at the wire. An adversarial-ML
    attacker reading the raw bits learns exactly which detectors fired
    and can craft the next epoch's input around them. Instead the
    response carries:
      - `flag_set_token` — an opaque token over (flags, wallet, epoch);
        equal tokens within an (agent, epoch) tuple, otherwise opaque
      - `flag_count`     — popcount; "how many detectors fired" without
        revealing which
      - `immediate_red`  — the ONE flag-derived signal a consumer must
        act on (fast-path red)
    """
    schema_version: int = Field(SCHEMA_VERSION, alias="_v")
    agent_wallet:   str
    epoch:          int
    score:          int          # 0..1000
    alert_tier:     str          # "GREEN" | "YELLOW" | "RED"
    alert_tier_code: int         # 0 | 1 | 2 (matches on-chain enum)
    flag_set_token: str          # VULN-24 opaque token (NOT the raw bitmask)
    flag_count:     int          # popcount of the underlying bitmask
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
# Diagnosis endpoint (Day 34, Phase-1, off-chain)
# =============================================================================
#
# The diagnosis surface returns the structured breakdown the scorer
# already computes: per-dimension `{score, max_score, sub_scores,
# flags}`, weighted contributions that sum to the composite, and the
# decoded labels + remediation hints the web app renders.
#
# An EXPLICIT `attestation` field marks the tier of trust. Day-34 is
# `"off_chain_v1"`: the data is faithful to the oracle's epoch_runner
# output but is NOT yet carried by a threshold-signed certificate. A
# consumer that requires an attested diagnosis must wait for Phase-2
# (cert v2), at which point the same shape will be served with
# `attestation: "cert_v2"`. The field is part of the wire contract
# precisely so a switch-statement can branch on it.


class DimensionBreakdownEntry(BaseModel):
    """One dimension's slice of the diagnosis. Mirrors
    `oracle.diagnosis.DimensionBreakdown` field for field; the
    `score_normalised` derived value is included so a consumer doesn't
    have to redo the divide."""
    dimension:        str
    score:            int
    max_score:        int
    score_normalised: float
    flags:            int
    sub_scores:       dict[str, float]
    algo_version:     int


class DecodedFlagLabel(BaseModel):
    """One legacy (low-32-bit) flag bit decoded through the Day-33
    taxonomy. The decode is best-effort: bits that exist in the
    aggregated `flags` but have no taxonomy entry (e.g. a per-dimension
    bit the high-level FailureMode doesn't model yet) are NOT raised
    here — they appear in `undecoded_flag_bits`."""
    name:        str
    bit:         int
    description: str
    severity:    str          # "INFO" | "LOW" | "MED" | "HIGH" | "CRITICAL"
    owasp_refs:  list[str]


class RemediationHint(BaseModel):
    """A single suggested remediation derived from the decoded labels.

    The set is the union of `default_remediation` across every decoded
    label — i.e. *if these labels were the diagnosis, here are the
    actions the playbook suggests*. Day-34 surfaces hints only; the
    Phase-2 cert v2 will threshold-sign the bitmask itself."""
    name:        str
    bit:         int


class DiagnosisResponse(BaseModel):
    """`GET /agents/{wallet}/diagnosis` and
    `…/diagnosis/{epoch}` — the off-chain diagnosis surface.

    The `attestation` field is part of the wire contract: a consumer
    that hashes this response into its own audit chain MUST switch on
    it so the Phase-1 / Phase-2 transition is observable.
    """
    schema_version:    int                          = Field(SCHEMA_VERSION, alias="_v")
    attestation:       Literal["off_chain_v1"]      = DIAGNOSIS_ATTESTATION_OFF_CHAIN_V1

    agent_wallet:      str
    epoch:             int
    score:             int                           # 0..1000 composite
    alert_tier:        str                           # "GREEN" | "YELLOW" | "RED"
    alert_tier_code:   int                           # 0 | 1 | 2
    immediate_red:     bool

    dimensions:                 list[DimensionBreakdownEntry]
    weighted_contributions:     dict[str, int]       # sums to `score` (± rounding)

    flags:                      int                  # u32, aggregated legacy bitmask
    decoded_labels:             list[DecodedFlagLabel]
    undecoded_flag_bits:        list[int]            # bits set but not in taxonomy
    remediation_hints:          list[RemediationHint]
    aggregate_severity:         str                  # max severity over decoded_labels

    confidence:                 int                   # 0..1000
    gaming_detected:            bool
    gaming_drop_fraction:       float
    delta_clamped:              bool

    scoring_algo_version:       int
    scoring_weights_version:    int
    scoring_schema_fingerprint: str
    baseline_stats_hash:        str

    computed_at:                datetime

    model_config = ConfigDict(populate_by_name=True)


# =============================================================================
# Safe-score endpoint (VULN-23) — DeFi consumer guard rails over REST
# =============================================================================
#
# This shape mirrors the SDK's `SafeScoreResult` discriminated union. The
# `ok` field is the discriminator a protocol switches on; when `ok=false`
# the protocol MUST refuse the operation — never default-allow.

class SafeScoreVelocityWindow(BaseModel):
    min_score: int
    max_score: int
    epochs:    list[int]


class SafeScoreResponse(BaseModel):
    """`GET /agents/{wallet}/safe_score` — guarded current score.

    The discriminator is `ok`:
      - ok=true  → `score` + `alert_tier` + `velocity_window` populated
      - ok=false → `reason` + `detail` populated; `score` is null

    `reason` is the machine-readable signal a DeFi protocol switches on:
      STALE_CERT, VELOCITY_EXCEEDED, INSUFFICIENT_HISTORY
    """
    schema_version:    int = Field(SCHEMA_VERSION, alias="_v")
    agent_wallet:      str
    ok:                bool
    # populated when ok=True
    score:             int | None              = None
    alert_tier:        str | None              = None
    alert_tier_code:   int | None              = None
    epoch:             int | None              = None
    issued_at_unix:    int | None              = None
    velocity_window:   SafeScoreVelocityWindow | None = None
    # populated when ok=False
    reason:            str | None              = None
    detail:            str | None              = None

    model_config = ConfigDict(populate_by_name=True)


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
# Integrations leaderboard (DBP-4c) — public Verified-Integrator ranking
# =============================================================================
#
# A Verified Integrator's safe-reader share is
#   safe_score_calls / (safe_score_calls + raw_score_calls)
# over the lifetime of the API process (the counter is monotonic and
# resets only on restart — like every other Prometheus counter the
# service emits). The leaderboard endpoint exposes the same shape a
# dashboard or public-facing "integrity score" widget would read.

class IntegrationLeaderboardEntry(BaseModel):
    """One Verified-Integrator's row.

    `safe_share` ∈ [0.0, 1.0]; a partner with zero observed calls is
    listed with `total_calls = 0` and `safe_share = None` so consumers
    can distinguish "new partner, no signal yet" from "partner is at
    0% safe share".
    """
    partner_wallet:   str
    safe_calls:       int
    raw_calls:        int
    total_calls:      int
    safe_share:       float | None  # None == no observed calls


class IntegrationLeaderboardResponse(BaseModel):
    """`GET /integrations/leaderboard` — public Verified-Integrator ranking.

    The list is sorted descending by `safe_share` with a tiebreak on
    `total_calls` (more traffic ranks higher among ties). Partners with
    zero observed calls appear at the bottom in `partner_wallet` order
    so the response is deterministic for testing + caching.
    """
    schema_version: int = Field(SCHEMA_VERSION, alias="_v")
    ranking:        list[IntegrationLeaderboardEntry]

    model_config = ConfigDict(populate_by_name=True)


# =============================================================================
# Errors
# =============================================================================

class ErrorResponse(BaseModel):
    error:   str
    detail:  str | None = None
