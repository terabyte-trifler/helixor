"""
tests/test_diagnosis.py — Day-34 Phase-1 diagnosis endpoints.

Covers the off-chain diagnosis surface end-to-end:
  - repo Protocol + in-memory shape
  - DiagnosisRecord invariants
  - GET /agents/{wallet}/diagnosis (latest)
  - GET /agents/{wallet}/diagnosis/{epoch}
  - flag decode + remediation hint wiring
  - response field contract (attestation, _v alias, provenance chain)
  - failure paths (404, 400, malformed inputs)

The diagnosis_repo fixture in conftest.py seeds three records:
  - WALLET_A epoch 28  (alert YELLOW, flags=0x01 PROVISIONAL)
  - WALLET_A epoch 29  (alert GREEN,  flags=0x00 no labels)
  - WALLET_B epoch 29  (alert RED,    flags=0x09 PROVISIONAL|IMMEDIATE_RED,
                        immediate_red=True)
"""

from __future__ import annotations

import pytest

from api.diagnosis_repo import (
    DiagnosisRecord,
    DimensionBreakdown,
    InMemoryDiagnosisRepo,
)
from tests.conftest import (
    REF_TS,
    WALLET_A,
    WALLET_B,
    WALLET_UNKNOWN,
    _synthetic_diagnosis,
)


# =============================================================================
# A — Repo invariants
# =============================================================================

class TestInMemoryDiagnosisRepo:

    def test_empty_repo_returns_none(self):
        repo = InMemoryDiagnosisRepo()
        assert repo.latest_diagnosis(WALLET_A) is None
        assert repo.diagnosis_at_epoch(WALLET_A, 1) is None
        assert repo.known_agents() == []

    def test_add_and_lookup_latest(self):
        repo = InMemoryDiagnosisRepo()
        repo.add(_synthetic_diagnosis(
            wallet=WALLET_A, epoch=10, score=600, alert_tier=1,
            immediate_red=False, flags=0,
        ))
        assert repo.latest_diagnosis(WALLET_A).epoch == 10

    def test_add_many_sorts_by_epoch(self):
        repo = InMemoryDiagnosisRepo()
        repo.add_many([
            _synthetic_diagnosis(
                wallet=WALLET_A, epoch=12, score=600,
                alert_tier=1, immediate_red=False, flags=0,
            ),
            _synthetic_diagnosis(
                wallet=WALLET_A, epoch=10, score=600,
                alert_tier=1, immediate_red=False, flags=0,
            ),
            _synthetic_diagnosis(
                wallet=WALLET_A, epoch=11, score=600,
                alert_tier=1, immediate_red=False, flags=0,
            ),
        ])
        # Latest is the highest epoch regardless of insertion order.
        assert repo.latest_diagnosis(WALLET_A).epoch == 12

    def test_reinsert_replaces_same_epoch(self):
        repo = InMemoryDiagnosisRepo()
        repo.add(_synthetic_diagnosis(
            wallet=WALLET_A, epoch=10, score=600,
            alert_tier=1, immediate_red=False, flags=0,
        ))
        repo.add(_synthetic_diagnosis(
            wallet=WALLET_A, epoch=10, score=700,
            alert_tier=0, immediate_red=False, flags=0,
        ))
        rec = repo.diagnosis_at_epoch(WALLET_A, 10)
        assert rec.score == 700
        assert rec.alert_tier == 0

    def test_known_agents_sorted(self):
        repo = InMemoryDiagnosisRepo()
        repo.add(_synthetic_diagnosis(
            wallet=WALLET_B, epoch=1, score=500,
            alert_tier=1, immediate_red=False, flags=0,
        ))
        repo.add(_synthetic_diagnosis(
            wallet=WALLET_A, epoch=1, score=500,
            alert_tier=1, immediate_red=False, flags=0,
        ))
        assert repo.known_agents() == sorted([WALLET_A, WALLET_B])


# =============================================================================
# B — DiagnosisRecord invariants
# =============================================================================

class TestDiagnosisRecordInvariants:

    def test_score_out_of_range_rejected(self):
        with pytest.raises(ValueError, match="score"):
            _synthetic_diagnosis(
                wallet=WALLET_A, epoch=1, score=1001,
                alert_tier=0, immediate_red=False, flags=0,
            )

    def test_alert_tier_invalid_rejected(self):
        with pytest.raises(ValueError, match="alert_tier"):
            _synthetic_diagnosis(
                wallet=WALLET_A, epoch=1, score=500,
                alert_tier=5, immediate_red=False, flags=0,
            )

    def test_epoch_below_one_rejected(self):
        with pytest.raises(ValueError, match="epoch"):
            _synthetic_diagnosis(
                wallet=WALLET_A, epoch=0, score=500,
                alert_tier=1, immediate_red=False, flags=0,
            )

    def test_flags_must_fit_u32(self):
        with pytest.raises(ValueError, match="u32"):
            _synthetic_diagnosis(
                wallet=WALLET_A, epoch=1, score=500,
                alert_tier=1, immediate_red=False,
                flags=0x1_0000_0000,
            )

    def test_dimension_breakdown_invariants(self):
        with pytest.raises(ValueError, match="outside"):
            DimensionBreakdown(
                dimension="drift", score=999, max_score=200,
                flags=0, sub_scores={}, algo_version=1,
            )


# =============================================================================
# C — GET /agents/{wallet}/diagnosis (current epoch)
# =============================================================================

class TestAgentDiagnosisCurrent:

    def test_returns_latest_epoch(self, client):
        r = client.get(f"/agents/{WALLET_A}/diagnosis")
        assert r.status_code == 200
        body = r.json()
        assert body["agent_wallet"] == WALLET_A
        assert body["epoch"] == 29
        assert body["score"] == 920
        assert body["alert_tier"] == "GREEN"
        assert body["alert_tier_code"] == 0

    def test_attestation_tag_is_off_chain_v1(self, client):
        body = client.get(f"/agents/{WALLET_A}/diagnosis").json()
        assert body["attestation"] == "off_chain_v1"

    def test_schema_version_field_present(self, client):
        body = client.get(f"/agents/{WALLET_A}/diagnosis").json()
        assert body["_v"] == 2

    def test_dimensions_cover_all_five(self, client):
        body = client.get(f"/agents/{WALLET_A}/diagnosis").json()
        names = sorted(d["dimension"] for d in body["dimensions"])
        assert names == sorted([
            "drift", "anomaly", "performance", "consistency", "security",
        ])

    def test_score_normalised_derived(self, client):
        body = client.get(f"/agents/{WALLET_A}/diagnosis").json()
        for d in body["dimensions"]:
            assert 0.0 <= d["score_normalised"] <= 1.0
            assert abs(d["score_normalised"] - d["score"] / d["max_score"]) < 1e-9

    def test_weighted_contributions_present(self, client):
        body = client.get(f"/agents/{WALLET_A}/diagnosis").json()
        contribs = body["weighted_contributions"]
        assert set(contribs.keys()) == {
            "drift", "anomaly", "performance", "consistency", "security",
        }
        # Contributions sum to score in the synthetic fixture by construction.
        assert sum(contribs.values()) == body["score"]

    def test_provenance_fields_passed_through(self, client):
        body = client.get(f"/agents/{WALLET_A}/diagnosis").json()
        assert body["scoring_algo_version"] == 2
        assert body["scoring_weights_version"] == 1
        assert body["scoring_schema_fingerprint"] == "f" * 64
        assert body["baseline_stats_hash"] == "b" * 64

    def test_unknown_agent_returns_404(self, client):
        r = client.get(f"/agents/{WALLET_UNKNOWN}/diagnosis")
        assert r.status_code == 404
        assert r.json()["error"] == "not_found"
        assert WALLET_UNKNOWN in r.json()["detail"]

    def test_immediate_red_propagates(self, client):
        body = client.get(f"/agents/{WALLET_B}/diagnosis").json()
        assert body["alert_tier"] == "RED"
        assert body["alert_tier_code"] == 2
        assert body["immediate_red"] is True

    def test_no_decoded_labels_when_flags_zero(self, client):
        body = client.get(f"/agents/{WALLET_A}/diagnosis").json()
        # WALLET_A epoch 29 has flags=0x00 in the fixture.
        assert body["flags"] == 0
        assert body["decoded_labels"] == []
        assert body["undecoded_flag_bits"] == []
        assert body["remediation_hints"] == []

    def test_severity_floor_is_info_when_no_labels(self, client):
        body = client.get(f"/agents/{WALLET_A}/diagnosis").json()
        assert body["aggregate_severity"] == "INFO"


# =============================================================================
# D — GET /agents/{wallet}/diagnosis/{epoch}
# =============================================================================

class TestAgentDiagnosisAtEpoch:

    def test_returns_specific_epoch(self, client):
        r = client.get(f"/agents/{WALLET_A}/diagnosis/28")
        assert r.status_code == 200
        body = r.json()
        assert body["epoch"] == 28
        assert body["score"] == 851
        assert body["alert_tier"] == "YELLOW"

    def test_missing_epoch_404(self, client):
        r = client.get(f"/agents/{WALLET_A}/diagnosis/99")
        assert r.status_code == 404

    def test_epoch_below_one_rejected(self, client):
        r = client.get(f"/agents/{WALLET_A}/diagnosis/0")
        assert r.status_code == 400
        assert "epoch" in r.json()["detail"]


# =============================================================================
# E — Flag decode + remediation wiring (Day-33 → Day-34)
# =============================================================================

class TestFlagDecodeWiring:

    def test_provisional_bit_decoded_for_wallet_a_epoch_28(self, client):
        body = client.get(f"/agents/{WALLET_A}/diagnosis/28").json()
        # Fixture sets flags=0x01 = bit 0 = PROVISIONAL.
        assert body["flags"] == 0x01
        names = [label["name"] for label in body["decoded_labels"]]
        assert "PROVISIONAL" in names

    def test_wallet_b_decodes_immediate_red(self, client):
        body = client.get(f"/agents/{WALLET_B}/diagnosis/29").json()
        # Fixture sets flags=0x09 = PROVISIONAL (bit 0) | IMMEDIATE_RED (bit 3).
        names = sorted(label["name"] for label in body["decoded_labels"])
        assert "PROVISIONAL" in names
        assert "IMMEDIATE_RED" in names

    def test_decoded_labels_carry_severity(self, client):
        body = client.get(f"/agents/{WALLET_B}/diagnosis/29").json()
        for label in body["decoded_labels"]:
            assert label["severity"] in (
                "INFO", "LOW", "MED", "HIGH", "CRITICAL",
            )

    def test_decoded_labels_carry_owasp_refs(self, client):
        body = client.get(f"/agents/{WALLET_B}/diagnosis/29").json()
        # Each label has an owasp_refs list (possibly empty for legacy bits).
        for label in body["decoded_labels"]:
            assert isinstance(label["owasp_refs"], list)

    def test_remediation_hints_present_for_immediate_red(self, client):
        body = client.get(f"/agents/{WALLET_B}/diagnosis/29").json()
        # IMMEDIATE_RED's metadata declares at least one remediation code
        # in the Day-33 LABEL_METADATA mapping; the response surfaces them.
        assert len(body["remediation_hints"]) >= 1
        for hint in body["remediation_hints"]:
            assert isinstance(hint["name"], str) and hint["name"]
            assert isinstance(hint["bit"], int) and hint["bit"] >= 0

    def test_aggregate_severity_max_of_set_bits(self, client):
        # WALLET_B's flags include IMMEDIATE_RED; severity should be elevated
        # above INFO (the empty-mask floor).
        body = client.get(f"/agents/{WALLET_B}/diagnosis/29").json()
        assert body["aggregate_severity"] != "INFO"


# =============================================================================
# F — Response shape stability (forward-compat / wire contract)
# =============================================================================

class TestResponseShape:

    def test_contains_all_top_level_fields(self, client):
        body = client.get(f"/agents/{WALLET_A}/diagnosis").json()
        required = {
            "_v", "attestation", "agent_wallet", "epoch", "score",
            "alert_tier", "alert_tier_code", "immediate_red",
            "dimensions", "weighted_contributions", "flags",
            "decoded_labels", "undecoded_flag_bits", "remediation_hints",
            "aggregate_severity", "confidence", "gaming_detected",
            "gaming_drop_fraction", "delta_clamped",
            "scoring_algo_version", "scoring_weights_version",
            "scoring_schema_fingerprint", "baseline_stats_hash",
            "computed_at",
        }
        assert required.issubset(set(body.keys()))

    def test_dimension_entry_shape(self, client):
        body = client.get(f"/agents/{WALLET_A}/diagnosis").json()
        d = body["dimensions"][0]
        required = {
            "dimension", "score", "max_score", "score_normalised",
            "flags", "sub_scores", "algo_version",
        }
        assert required.issubset(set(d.keys()))

    def test_cache_control_is_operational(self, client):
        r = client.get(f"/agents/{WALLET_A}/diagnosis")
        assert r.headers["Cache-Control"] == "private, no-store"
