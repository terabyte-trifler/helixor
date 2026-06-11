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


# Day-40 — Consumer surfaces v2. The wire surface for diagnosis +
# evidence is now stable enough for insurers/marketplaces to depend on,
# and the SDK consumes _v as a forward-compat gate. The bump is
# strictly additive: every Day-34/Day-39 field is preserved; clients
# pinned to v1 still receive the same field set. Any consumer that
# branches on `_v` should treat `>=1` as "diagnosis + evidence shape is
# stable" and reserve a future `>=3` bump for the next breaking change.
SCHEMA_VERSION = 2

# Phase-1 diagnosis attestation tag. Day-34 surfaces a non-threshold-
# attested diagnosis, so we mark every response with this literal — the
# consumer can switch on it. Phase-2 lifts the same fields into the
# threshold-signed cert v2, which will mark them `"cert_v2"`.
DIAGNOSIS_ATTESTATION_OFF_CHAIN_V1: Literal["off_chain_v1"] = "off_chain_v1"

# Day-39 evidence-DA attestation tag. Lifts to "threshold_attested" when
# the indexer has observed an on-chain `diagnosis_payload_hash` for the
# (agent, epoch) AND the bytes served here hash to the same value.
# Until either side shows up, the served record carries
# DIAGNOSIS_ATTESTATION_OFF_CHAIN_V1.
EVIDENCE_ATTESTATION_THRESHOLD: Literal["threshold_attested"] = "threshold_attested"


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
# Evidence DA endpoint (Day 39) — span-level evidence behind the on-chain hash
# =============================================================================
#
# The Day-38 HealthCertificate v2 attests to a `diagnosis_payload_hash` —
# a 32-byte SHA-256 of the canonical-JSON evidence payload. The bytes
# themselves do NOT go on-chain; they live in the indexer's
# `diagnosis_payloads` DA table and are served here. A consumer that
# fetches this endpoint:
#
#   1. Reads `payload_canonical_json` — the EXACT bytes the cluster signed.
#   2. Reads `payload_hash_hex` — convenience copy of sha256(bytes).
#   3. Reads `on_chain_hash_hex` — what cert v2 attests to (None if the
#      indexer hasn't seen the cert yet).
#   4. Recomputes sha256(payload_canonical_json) and verifies it equals
#      `on_chain_hash_hex`.
#
# `attestation` is the discriminator. It is "threshold_attested" iff
# steps 1-3 line up; otherwise "off_chain_v1" (same off-chain seam as
# the Day-34 diagnosis surface — a consumer that requires attested
# evidence MUST branch on this).


class EvidenceVerificationRecipe(BaseModel):
    """The hash-verification recipe the served bytes obey.

    A consumer follows these steps to verify the served payload bytes
    against the on-chain cert v2 field — none of them require trust in
    the API, only in the canonical-JSON dumper named here:

      hash_algo:    "sha256"
      hash_input:   "payload_canonical_json (the served bytes verbatim)"
      json_dumper:  "json.dumps(..., sort_keys=True,
                                separators=(',', ':'),
                                ensure_ascii=True)"

    This is the same dumper Day-23 baseline-hashing and Day-36 kernel
    JSON use — a consumer that reproduces the dumper byte-for-byte can
    re-derive every Helixor canonical hash without trusting the
    server's serialiser.
    """
    hash_algo:   str        # "sha256"
    hash_input:  str        # "payload_canonical_json"
    json_dumper: str        # the exact json.dumps args


class EvidenceResponse(BaseModel):
    """`GET /agents/{wallet}/diagnosis/{epoch}/evidence` — the off-chain
    DA payload behind the threshold-attested on-chain hash.

    `attestation` flips to "threshold_attested" iff the indexer has
    seen the cert v2 hash AND it matches sha256(payload_canonical_json).
    Otherwise "off_chain_v1" — the bytes are faithfully served but not
    yet bound to a threshold-signed cert.
    """
    schema_version:    int = Field(SCHEMA_VERSION, alias="_v")
    attestation:       Literal["off_chain_v1", "threshold_attested"]
    agent_wallet:      str
    epoch:             int
    taxonomy_version:  int                                 # u8 — Day-38 field
    signer_count:      int                                 # cluster signers
    payload_canonical_json: str                            # exact ASCII bytes
    payload_hash_hex:       str                            # sha256 hex of above
    on_chain_hash_hex:      str | None                     # cert v2 hex (or None)
    verification:           EvidenceVerificationRecipe
    computed_at:            datetime

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
