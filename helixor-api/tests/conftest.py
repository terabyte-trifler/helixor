"""Shared fixtures for the helixor-api test suite."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.auth import ApiKey, ApiKeyRegistry
from api.byzantine_repo import (
    ByzantineFlagRecord,
    ChallengeRecord,
    InMemoryByzantineRepo,
    NodeRevealRecord,
    StrikeSummary,
)
from api.cluster_health import (
    EpochSummary,
    InMemoryClusterHealthRepo,
    NodeHeartbeat,
)
from api.diagnosis_repo import (
    DiagnosisRecord,
    DimensionBreakdown,
    InMemoryDiagnosisRepo,
)
from api.rate_limit import SlidingWindowLimiter
from api.score_repo import InMemoryScoreRepo, ScoreRecord


# =============================================================================
# VULN-09 test wiring
# =============================================================================
#
# Every test fixture wires a single API key (`test-key-001` / secret
# `test-secret-001`) and injects the secret as an X-API-Key header on the
# default `client`. Tests of the auth gate use the `unauthed_client`
# fixture instead, which omits the header.
#
# Rate limits in tests are set to a HIGH cap so that no existing test
# accidentally trips 429. The VULN-09 rate-limit tests build their own
# app with low caps to exercise the limiter directly.

TEST_API_KEY_ID:     str = "test-key-001"
TEST_API_KEY_SECRET: str = "test-secret-001"
TEST_RATE_LIMIT_PER_MIN: int = 10_000


REF_TS = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Synthetic but well-shaped wallet placeholders (VULN-20)
# =============================================================================
#
# Every wallet/node string handed to the API after VULN-20 must be a
# valid base58 string of length 32..44 (Solana's Ed25519 pubkey shape).
# We pin a small set of deterministic constants here so tests stay
# readable: a test asks for `WALLET_A` and an alert message that says
# "agent A" still maps to a real-shaped value.
#
# All characters below are in the Bitcoin base58 alphabet (no 0/O/I/l).

WALLET_A          = "A1" * 22                    # "A1A1...A1" 44 chars
WALLET_B          = "B2" * 22
WALLET_UNKNOWN    = "Zz" * 22                    # an agent the repo never sees
NODE_0            = "N1" * 22
NODE_1            = "N2" * 22
NODE_2            = "N3" * 22                    # the Byzantine node
NODE_3            = "N4" * 22
NODE_4            = "N5" * 22
NODE_IDS          = (NODE_0, NODE_1, NODE_2, NODE_3, NODE_4)


# =============================================================================
# Per-test repo fixtures — populated with a small, predictable dataset
# =============================================================================

@pytest.fixture
def score_repo() -> InMemoryScoreRepo:
    repo = InMemoryScoreRepo()
    # Agent A: a YELLOW past, a GREEN now.
    repo.add(ScoreRecord(WALLET_A, 27, 700, 1, 0x02, False, 3, REF_TS))
    repo.add(ScoreRecord(WALLET_A, 28, 851, 1, 0x42, False, 3, REF_TS))
    repo.add(ScoreRecord(WALLET_A, 29, 920, 0, 0x00, False, 4, REF_TS))
    # Agent B: one cert, RED with immediate_red set.
    repo.add(ScoreRecord(WALLET_B, 29, 220, 2, 0xff, True,  5, REF_TS))
    return repo


@pytest.fixture
def byzantine_repo() -> InMemoryByzantineRepo:
    repo = InMemoryByzantineRepo()
    repo.add_flag(ByzantineFlagRecord(
        node_id=NODE_2, epoch=28,
        subject_agent=WALLET_A, accused_score=40,
        cluster_median=851, deviation=0.95,
    ))
    repo.add_flag(ByzantineFlagRecord(
        node_id=NODE_2, epoch=29,
        subject_agent=WALLET_B, accused_score=900,
        cluster_median=220, deviation=3.09,
    ))
    repo.set_strikes(StrikeSummary(
        node_id=NODE_2, strikes=2,
        flagged_epochs=(28, 29), challenged=False,
    ))
    repo.add_reveal(NodeRevealRecord(NODE_0, 28, WALLET_A, 851))
    repo.add_reveal(NodeRevealRecord(NODE_1, 28, WALLET_A, 850))
    repo.add_reveal(NodeRevealRecord(NODE_2, 28, WALLET_A,  40))
    repo.add_reveal(NodeRevealRecord(NODE_3, 28, WALLET_A, 853))
    repo.add_reveal(NodeRevealRecord(NODE_4, 28, WALLET_A, 851))
    repo.add_challenge(ChallengeRecord(
        challenge_index=0,
        accused_node=NODE_2,
        proof_type=0,
        subject_epoch=28,
        subject_agent=WALLET_A,
        accused_score=40,
        cluster_median=851,
        evidence_hash="b" * 64,
        status="pending",
        filed_at=1_750_000_000,
    ))
    return repo


@pytest.fixture
def cluster_repo() -> InMemoryClusterHealthRepo:
    repo = InMemoryClusterHealthRepo()
    for node_id in NODE_IDS:
        repo.add_heartbeat(NodeHeartbeat(
            node_id=node_id,
            last_seen_unix=1_750_000_000,
            epoch=29,
        ))
    repo.add_epoch(EpochSummary(
        epoch=28, submitted_count=2, agent_count=2,
        verified_nodes=NODE_IDS,
        byzantine_nodes=(NODE_2,),
        unreachable_nodes=(),
        elapsed_seconds=6.3,
        computed_at=REF_TS,
    ))
    repo.add_epoch(EpochSummary(
        epoch=29, submitted_count=2, agent_count=2,
        verified_nodes=(NODE_0, NODE_1, NODE_3, NODE_4),
        byzantine_nodes=(),
        unreachable_nodes=(NODE_2,),
        elapsed_seconds=5.8,
        computed_at=REF_TS,
    ))
    return repo


@pytest.fixture
def diagnosis_repo() -> InMemoryDiagnosisRepo:
    """Day-34 fixture: two diagnosis records that mirror the score_repo
    fixture's WALLET_A epoch-29 and WALLET_B epoch-29 rows. Per-dimension
    breakdown is synthetic but well-shaped — enough to exercise the
    response projection + decode wiring."""
    repo = InMemoryDiagnosisRepo()
    repo.add(_synthetic_diagnosis(
        wallet=WALLET_A, epoch=29, score=920, alert_tier=0,
        immediate_red=False,
        # IMMEDIATE_RED bit (1<<3) deliberately unset; CONSISTENCY_DRIFT
        # bit (1<<24, a per-dimension legacy bit) set to exercise the
        # undecoded-bit branch in the response. flag=0x00 = no bits.
        flags=0x00,
    ))
    repo.add(_synthetic_diagnosis(
        wallet=WALLET_A, epoch=28, score=851, alert_tier=1,
        immediate_red=False,
        # PROVISIONAL (1<<0) + IMMEDIATE_RED (1<<3) — but immediate_red
        # is False so a consumer can see the bit-vs-cert-tier distinction.
        # We just set PROVISIONAL for this row.
        flags=0x01,
    ))
    repo.add(_synthetic_diagnosis(
        wallet=WALLET_B, epoch=29, score=220, alert_tier=2,
        immediate_red=True,
        # IMMEDIATE_RED + several detector bits to exercise decode.
        flags=0x09,  # PROVISIONAL | IMMEDIATE_RED
    ))
    return repo


def _synthetic_diagnosis(
    *, wallet: str, epoch: int, score: int, alert_tier: int,
    immediate_red: bool, flags: int,
) -> DiagnosisRecord:
    """Build a minimal but valid DiagnosisRecord for tests."""
    # Per-dimension caps so the synthetic breakdown is always valid.
    dim_caps = [
        ("drift", 200), ("anomaly", 200), ("performance", 200),
        ("consistency", 200), ("security", 150),
    ]
    dims = {
        name: DimensionBreakdown(
            dimension=name,
            score=min(score // 5, max_score),
            max_score=max_score,
            flags=0,
            sub_scores={"primary": 0.5},
            algo_version=1,
        )
        for name, max_score in dim_caps
    }
    base = score // 5
    contributions = {
        "drift":       base,
        "anomaly":     base,
        "performance": base,
        "consistency": base,
        "security":    score - 4 * base,
    }
    return DiagnosisRecord(
        agent_wallet=wallet, epoch=epoch, score=score,
        alert_tier=alert_tier, immediate_red=immediate_red,
        dimensions=dims, weighted_contributions=contributions,
        flags=flags,
        confidence=900, gaming_detected=False, gaming_drop_fraction=0.0,
        delta_clamped=False,
        scoring_algo_version=2, scoring_weights_version=1,
        scoring_schema_fingerprint="f" * 64,
        baseline_stats_hash="b" * 64,
        computed_at=REF_TS,
    )


@pytest.fixture
def key_registry() -> ApiKeyRegistry:
    return ApiKeyRegistry([
        ApiKey.from_secret(
            key_id=TEST_API_KEY_ID,
            secret=TEST_API_KEY_SECRET,
            tier="test",
            rate_limit_per_minute=TEST_RATE_LIMIT_PER_MIN,
        ),
    ])


@pytest.fixture
def rate_limiter() -> SlidingWindowLimiter:
    # Fresh limiter per test — no cross-test bucket contamination.
    return SlidingWindowLimiter()


@pytest.fixture
def app(score_repo, byzantine_repo, cluster_repo, diagnosis_repo,
        key_registry, rate_limiter):
    return create_app(
        score_repo=score_repo,
        byzantine_repo=byzantine_repo,
        cluster_repo=cluster_repo,
        diagnosis_repo=diagnosis_repo,
        network="localnet",
        is_production=False,
        scoring_algo_version="v2.7",
        scoring_weights_version="w1",
        key_registry=key_registry,
        rate_limiter=rate_limiter,
        # Test default — well above anything any individual test triggers.
        public_rate_limit_per_minute=TEST_RATE_LIMIT_PER_MIN,
    )


@pytest.fixture
def client(app) -> TestClient:
    """Authenticated TestClient — every request carries the test key."""
    c = TestClient(app)
    c.headers["X-API-Key"] = TEST_API_KEY_SECRET
    return c


@pytest.fixture
def unauthed_client(app) -> TestClient:
    """TestClient with NO API key — for verifying the 401 path."""
    return TestClient(app)
