"""
tests/test_evidence_endpoint.py — Day-39 evidence DA endpoint.

Covers `GET /agents/{wallet}/diagnosis/{epoch}/evidence` end-to-end:

  * full round-trip: byte-identical canonical-JSON payload stored in the
    repo flows through the HTTP response and a verifier-side recompute
    of sha256(payload_canonical_json) lands on `payload_hash_hex`.
  * attestation discriminator flips: "off_chain_v1" when no cert v2 has
    been observed; "threshold_attested" after the indexer records the
    on-chain hash AND it matches the served bytes.
  * mismatched on-chain hash stays "off_chain_v1" — a consumer that
    requires attested evidence MUST refuse in this state.
  * 404 when (agent, epoch) has no evidence; 400 on bad epoch; 400 on
    malformed wallet.
  * cache-control header pins to the operational-data short-TTL.

Builds the canonical-JSON evidence bytes locally — no oracle import —
because the API contract is independent of the oracle's builder. The
shape mirrors `diagnosis/evidence_payload.py` so a future schema bump
fails this file too.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.evidence_repo import (
    EvidencePayloadRecord,
    InMemoryEvidencePayloadRepo,
)
from tests.conftest import (
    REF_TS,
    TEST_API_KEY_SECRET,
    WALLET_A,
    WALLET_B,
    WALLET_UNKNOWN,
)


# =============================================================================
# Local canonical-JSON helpers — mirror diagnosis/evidence_payload.py
# =============================================================================
#
# The API does not import the oracle; the test must not either. The
# canonical dumper is one line and pinning the bytes locally is exactly
# what a third-party verifier would do.

def _canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _build_payload(
    *,
    taxonomy_version: str = "1",
    kernel_manifest:  str = "a" * 64,
    dimensions:       list[dict] | None = None,
    findings:         list[dict] | None = None,
) -> dict:
    """Build the Day-39 wire shape — enough to exercise the endpoint."""
    return {
        "taxonomy_version": taxonomy_version,
        "kernel_manifest":  kernel_manifest,
        "dimensions": dimensions if dimensions is not None else [
            {
                "dimension": "drift", "score": 920, "max_score": 1000,
                "flags": 0, "sub_scores": {"primary": 0.5},
                "algo_version": 1,
            },
        ],
        "findings": findings if findings is not None else [
            {
                "bit":        35,
                "label":      "TOOL_LOOP",
                "confidence": 0.95,
                "evidence_spans": [
                    {"slot": 12345, "tx_sig": "sig1", "ix_index": 0, "note": ""},
                ],
            },
        ],
    }


def _record_for(
    *,
    wallet:           str,
    epoch:            int,
    payload:          dict,
    signer_count:     int = 5,
    taxonomy_version: int = 1,
    on_chain_hash:    bytes | None = None,
    computed_at:      datetime = REF_TS,
) -> EvidencePayloadRecord:
    """Materialise the wire payload into the repo record shape."""
    payload_bytes = _canonical(payload)
    return EvidencePayloadRecord(
        agent_wallet=wallet,
        epoch=epoch,
        payload_bytes=payload_bytes,
        payload_hash=_sha256(payload_bytes),
        taxonomy_version=taxonomy_version,
        signer_count=signer_count,
        computed_at=computed_at,
        on_chain_hash=on_chain_hash,
    )


# =============================================================================
# Fixtures — fresh evidence_repo + an app wired with it
# =============================================================================

@pytest.fixture
def evidence_repo() -> InMemoryEvidencePayloadRepo:
    """Seed: WALLET_A @ epoch 29 unattested. (Other rows added per test.)"""
    repo = InMemoryEvidencePayloadRepo()
    repo.add(_record_for(
        wallet=WALLET_A, epoch=29,
        payload=_build_payload(),
    ))
    return repo


@pytest.fixture
def app_with_evidence(
    score_repo, byzantine_repo, cluster_repo, diagnosis_repo,
    evidence_repo, key_registry, rate_limiter,
):
    return create_app(
        score_repo=score_repo,
        byzantine_repo=byzantine_repo,
        cluster_repo=cluster_repo,
        diagnosis_repo=diagnosis_repo,
        evidence_repo=evidence_repo,
        network="localnet",
        is_production=False,
        scoring_algo_version="v2.7",
        scoring_weights_version="w1",
        key_registry=key_registry,
        rate_limiter=rate_limiter,
        public_rate_limit_per_minute=10_000,
    )


@pytest.fixture
def evidence_client(app_with_evidence) -> TestClient:
    c = TestClient(app_with_evidence)
    c.headers["X-API-Key"] = TEST_API_KEY_SECRET
    return c


# =============================================================================
# A — full round-trip: served bytes hash to `payload_hash_hex`
# =============================================================================

class TestEvidenceRoundTrip:

    def test_200_ok(self, evidence_client):
        r = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/29/evidence"
        )
        assert r.status_code == 200

    def test_recomputed_sha256_matches_payload_hash_hex(self, evidence_client):
        """The contract: a verifier hashes the served bytes and the result
        equals the served `payload_hash_hex`. No trust in the API."""
        body = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/29/evidence"
        ).json()
        recomputed = hashlib.sha256(
            body["payload_canonical_json"].encode("ascii")
        ).hexdigest()
        assert recomputed == body["payload_hash_hex"]

    def test_served_payload_round_trips_through_json_loads(self, evidence_client):
        """A consumer that does json.loads on the served bytes gets a dict
        that re-canonicalises to the SAME bytes — pins the canonical
        dumper contract end-to-end."""
        body = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/29/evidence"
        ).json()
        served = body["payload_canonical_json"]
        decoded = json.loads(served)
        re_canon = json.dumps(
            decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        )
        assert re_canon == served

    def test_top_level_fields_present(self, evidence_client):
        body = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/29/evidence"
        ).json()
        assert body["agent_wallet"] == WALLET_A
        assert body["epoch"] == 29
        assert body["taxonomy_version"] == 1
        assert body["signer_count"] == 5
        assert isinstance(body["payload_canonical_json"], str)
        assert isinstance(body["payload_hash_hex"], str)
        assert len(body["payload_hash_hex"]) == 64

    def test_verification_recipe_present(self, evidence_client):
        body = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/29/evidence"
        ).json()
        v = body["verification"]
        assert v["hash_algo"] == "sha256"
        assert v["hash_input"] == "payload_canonical_json"
        assert "sort_keys=True" in v["json_dumper"]
        assert "ensure_ascii=True" in v["json_dumper"]

    def test_schema_version_field_present(self, evidence_client):
        body = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/29/evidence"
        ).json()
        assert body["_v"] == 1


# =============================================================================
# B — attestation discriminator flips
# =============================================================================

class TestAttestationDiscriminator:

    def test_off_chain_v1_when_no_on_chain_hash_seen(self, evidence_client):
        body = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/29/evidence"
        ).json()
        assert body["attestation"] == "off_chain_v1"
        assert body["on_chain_hash_hex"] is None

    def test_threshold_attested_when_on_chain_hash_matches(
        self, app_with_evidence, evidence_client,
    ):
        """After the indexer records a matching on-chain hash, the
        served record carries `attestation: "threshold_attested"`."""
        # Recompute what the on-chain hash WOULD be — same bytes we stored.
        payload_bytes = _canonical(_build_payload())
        repo: InMemoryEvidencePayloadRepo = app_with_evidence.state.evidence_repo
        repo.record_on_chain_hash(WALLET_A, 29, _sha256(payload_bytes))

        body = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/29/evidence"
        ).json()
        assert body["attestation"] == "threshold_attested"
        assert body["on_chain_hash_hex"] == _sha256(payload_bytes).hex()
        # The bytes recompute the same hash — the consumer's check.
        assert hashlib.sha256(
            body["payload_canonical_json"].encode("ascii")
        ).hexdigest() == body["on_chain_hash_hex"]

    def test_mismatched_on_chain_hash_stays_off_chain(
        self, app_with_evidence, evidence_client,
    ):
        """If the indexer records an on-chain hash that does NOT match the
        served bytes, the attestation stays "off_chain_v1" — a consumer
        that requires attested evidence MUST refuse in this state."""
        repo: InMemoryEvidencePayloadRepo = app_with_evidence.state.evidence_repo
        # A different 32-byte hash — guaranteed not to match.
        repo.record_on_chain_hash(WALLET_A, 29, b"\xff" * 32)

        body = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/29/evidence"
        ).json()
        assert body["attestation"] == "off_chain_v1"
        # The on-chain hash is still surfaced — the consumer needs both
        # sides to detect the divergence.
        assert body["on_chain_hash_hex"] == ("ff" * 32)


# =============================================================================
# C — failure paths
# =============================================================================

class TestFailurePaths:

    def test_unknown_agent_returns_404(self, evidence_client):
        r = evidence_client.get(
            f"/agents/{WALLET_UNKNOWN}/diagnosis/29/evidence"
        )
        assert r.status_code == 404

    def test_unknown_epoch_returns_404(self, evidence_client):
        r = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/9999/evidence"
        )
        assert r.status_code == 404

    def test_epoch_zero_returns_400(self, evidence_client):
        r = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/0/evidence"
        )
        assert r.status_code == 400

    def test_negative_epoch_rejected(self, evidence_client):
        r = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/-1/evidence"
        )
        # FastAPI's int parser rejects -1 in path? Actually -1 fits int,
        # so the route runs and our 400 guard fires.
        assert r.status_code in (400, 422)

    def test_malformed_wallet_returns_400(self, evidence_client):
        r = evidence_client.get(
            "/agents/not-a-base58-wallet!/diagnosis/29/evidence"
        )
        assert r.status_code == 400


# =============================================================================
# D — independence across (agent, epoch)
# =============================================================================

class TestMultipleAgentsEpochs:

    def test_distinct_agents_distinct_payloads(
        self, app_with_evidence, evidence_client,
    ):
        """Two agents at the same epoch get independent payloads — the
        repo's (agent, epoch) secondary index is what the route reads."""
        repo: InMemoryEvidencePayloadRepo = app_with_evidence.state.evidence_repo
        # Distinct payload for WALLET_B — different findings.
        payload_b = _build_payload(findings=[
            {
                "bit":        12,
                "label":      "UNKNOWN_BIT_12",  # bit 12 may not have metadata
                "confidence": 0.7,
                "evidence_spans": [],
            },
        ])
        repo.add(_record_for(
            wallet=WALLET_B, epoch=29, payload=payload_b, signer_count=4,
        ))

        body_a = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/29/evidence"
        ).json()
        body_b = evidence_client.get(
            f"/agents/{WALLET_B}/diagnosis/29/evidence"
        ).json()
        assert body_a["payload_hash_hex"] != body_b["payload_hash_hex"]
        assert body_a["agent_wallet"] == WALLET_A
        assert body_b["agent_wallet"] == WALLET_B
        assert body_b["signer_count"] == 4

    def test_same_agent_distinct_epochs_distinct_payloads(
        self, app_with_evidence, evidence_client,
    ):
        repo: InMemoryEvidencePayloadRepo = app_with_evidence.state.evidence_repo
        repo.add(_record_for(
            wallet=WALLET_A, epoch=28,
            payload=_build_payload(kernel_manifest="b" * 64),
        ))

        body_29 = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/29/evidence"
        ).json()
        body_28 = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/28/evidence"
        ).json()
        assert body_29["epoch"] == 29
        assert body_28["epoch"] == 28
        assert body_29["payload_hash_hex"] != body_28["payload_hash_hex"]


# =============================================================================
# E — operational headers
# =============================================================================

class TestCacheHeader:

    def test_cache_control_present(self, evidence_client):
        r = evidence_client.get(
            f"/agents/{WALLET_A}/diagnosis/29/evidence"
        )
        assert r.status_code == 200
        # An operational route — the response MUST carry an explicit
        # cache directive (no silent caching by intermediaries). The
        # attestation tag can flip the moment the indexer records the
        # cert, so a stale cached copy is a soundness hazard.
        cc = r.headers.get("cache-control", "").lower()
        assert cc != ""
        assert ("no-store" in cc) or ("max-age" in cc)
