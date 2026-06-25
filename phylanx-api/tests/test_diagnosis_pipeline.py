"""
tests/test_diagnosis_pipeline.py — Day-34 oracle → API round-trip.

THE DAY-34 SPEC
---------------
> Done when: endpoint live; ~25 new API tests; ONE PIPELINE ROUND-TRIP
> TEST (run epoch → diagnosis served); audit driver still green.

This is that one round-trip. It:

  1. Runs a real oracle epoch through `run_epoch` against the Day-14
     `stable_agent` profile (deterministic, well-shaped).
  2. Materialises a `DiagnosisRecord` from the resulting EpochReport via
     the `EpochReport.diagnosis_records()` helper added in Day-34.
  3. Feeds the record into an `InMemoryDiagnosisRepo`.
  4. Builds the API app against that repo and asks the
     `/agents/{wallet}/diagnosis` endpoint for the same agent.
  5. Asserts the served payload matches the oracle's score, alert tier,
     immediate_red, dimensions keyset, and provenance fields.

If anything in the oracle's epoch_runner → diagnosis.record →
api.diagnosis_repo → api.app projection drifts, this test catches it
before the canary surface goes out the door.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

# The Day-14 synthetic agent profiles live in phylanx-oracle/tests; make
# them importable without coupling phylanx-api's tests/ layout to the
# oracle's package layout. Both directories are repo-local.
_ORACLE_ROOT = Path(__file__).resolve().parents[2] / "phylanx-oracle"
if str(_ORACLE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ORACLE_ROOT))

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.auth import ApiKey, ApiKeyRegistry
from api.byzantine_repo import InMemoryByzantineRepo
from api.cluster_health import InMemoryClusterHealthRepo
from api.diagnosis_repo import InMemoryDiagnosisRepo
from api.score_repo import InMemoryScoreRepo


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


# A real Solana-shaped base58 wallet placeholder. We override the wallet
# the oracle's stable_agent profile would use so the API's wallet
# validator accepts it (VULN-20).
WALLET_PIPELINE = "P1" * 22


def _recording_submit():
    calls: list[dict] = []

    def _submit(wallet: str, score_result) -> dict:
        record = {"wallet": wallet, "score": score_result.score}
        calls.append(record)
        return record

    return _submit, calls


def _load_agent_profiles():
    """Load phylanx-oracle's tests/oracle/agent_profiles.py as a free
    module. We cannot `import tests.oracle.agent_profiles` because the
    `tests` package on sys.path is the phylanx-api one — same name,
    different content. importlib.util sidesteps the package collision."""
    import importlib.util

    path = _ORACLE_ROOT / "tests" / "oracle" / "agent_profiles.py"
    spec = importlib.util.spec_from_file_location(
        "_phylanx_oracle_agent_profiles", path,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def pipeline_report():
    """Run a real oracle epoch over the Day-14 stable_agent profile."""
    from oracle.epoch_runner import AgentEpochInput, run_epoch

    profiles = _load_agent_profiles()
    gen, _ = profiles.ALL_PROFILES["stable_a"]
    base_input: AgentEpochInput = gen()
    # Replace the wallet with a well-shaped one (the profile fixtures use
    # short test strings; VULN-20 wants 32..44 chars base58).
    pipeline_input = AgentEpochInput(
        agent_wallet=WALLET_PIPELINE,
        baseline_transactions=base_input.baseline_transactions,
        current_transactions=base_input.current_transactions,
        baseline_window=base_input.baseline_window,
        current_window=base_input.current_window,
        security_context=base_input.security_context,
        market_context=base_input.market_context,
        consistency_context=base_input.consistency_context,
        previous_score=base_input.previous_score,
    )

    submit, _calls = _recording_submit()
    return run_epoch(
        epoch_id=34,
        agent_inputs=[pipeline_input],
        submit_fn=submit,
        computed_at=REF_END,
    )


@pytest.fixture
def pipeline_app(pipeline_report):
    """Build an API app whose diagnosis_repo holds the records derived
    from `pipeline_report`. Everything else is empty/minimal — this test
    is about the diagnosis projection, not other endpoints."""
    records = pipeline_report.diagnosis_records()
    diag_repo = InMemoryDiagnosisRepo(records=records)

    key_reg = ApiKeyRegistry([
        ApiKey.from_secret(
            key_id="pipe-test", secret="pipe-secret",
            tier="test", rate_limit_per_minute=10_000,
        ),
    ])
    return create_app(
        score_repo=InMemoryScoreRepo(),
        byzantine_repo=InMemoryByzantineRepo(),
        cluster_repo=InMemoryClusterHealthRepo(),
        diagnosis_repo=diag_repo,
        network="localnet",
        is_production=False,
        key_registry=key_reg,
        public_rate_limit_per_minute=10_000,
    )


@pytest.fixture
def pipeline_client(pipeline_app):
    c = TestClient(pipeline_app)
    c.headers["X-API-Key"] = "pipe-secret"
    return c


# =============================================================================
# The one round-trip test
# =============================================================================

class TestOracleToApiRoundTrip:

    def test_diagnosis_record_materialised_from_report(self, pipeline_report):
        records = pipeline_report.diagnosis_records()
        assert len(records) == 1
        rec = records[0]
        assert rec.agent_wallet == WALLET_PIPELINE
        assert rec.epoch == 34
        # The oracle's score landed in the record verbatim.
        oracle_result = pipeline_report.results[0]
        assert rec.score == oracle_result.score_result.score
        assert rec.flags == oracle_result.score_result.aggregated_flags

    def test_endpoint_serves_pipeline_diagnosis(self, pipeline_client,
                                                pipeline_report):
        r = pipeline_client.get(f"/agents/{WALLET_PIPELINE}/diagnosis")
        assert r.status_code == 200
        body = r.json()

        oracle_score = pipeline_report.results[0].score_result.score
        oracle_flags = pipeline_report.results[0].score_result.aggregated_flags
        oracle_immediate_red = pipeline_report.results[0].score_result.immediate_red

        assert body["agent_wallet"] == WALLET_PIPELINE
        assert body["epoch"] == 34
        assert body["score"] == oracle_score
        assert body["flags"] == oracle_flags
        assert body["immediate_red"] == oracle_immediate_red
        assert body["attestation"] == "off_chain_v1"
        # All five dimensions arrived intact.
        names = sorted(d["dimension"] for d in body["dimensions"])
        assert names == sorted(
            ["drift", "anomaly", "performance", "consistency", "security"],
        )
        # Provenance carried through.
        assert body["scoring_algo_version"] == \
            pipeline_report.results[0].score_result.scoring_algo_version
        assert body["baseline_stats_hash"] == \
            pipeline_report.results[0].score_result.baseline_stats_hash

    def test_specific_epoch_endpoint_serves_same_record(self, pipeline_client):
        r = pipeline_client.get(f"/agents/{WALLET_PIPELINE}/diagnosis/34")
        assert r.status_code == 200
        assert r.json()["epoch"] == 34

    def test_other_epoch_404(self, pipeline_client):
        r = pipeline_client.get(f"/agents/{WALLET_PIPELINE}/diagnosis/99")
        assert r.status_code == 404
