"""
tests/test_app.py — every phylanx-api route, happy + unhappy paths.

Tests use the FastAPI TestClient against an app built with the in-memory
repos from conftest.py. The same app shape ships to production with
TimescaleDB-backed repos; the route layer is the same.
"""

from __future__ import annotations

import pytest

from tests.conftest import (
    NODE_0, NODE_2, NODE_IDS, WALLET_A, WALLET_B, WALLET_UNKNOWN,
)


# =============================================================================
# /agents/{wallet}/health  — current score
# =============================================================================

class TestAgentHealthCurrent:

    def test_returns_latest_epoch(self, client):
        r = client.get(f"/agents/{WALLET_A}/health")
        assert r.status_code == 200
        body = r.json()
        assert body["agent_wallet"] == WALLET_A
        assert body["epoch"] == 29                  # latest, not 27 or 28
        assert body["score"] == 920
        assert body["alert_tier"] == "GREEN"
        assert body["alert_tier_code"] == 0
        assert body["signer_count"] == 4

    def test_schema_version_field_present(self, client):
        body = client.get(f"/agents/{WALLET_A}/health").json()
        assert body["_v"] == 2                      # SCHEMA_VERSION (Day-40 bump)

    def test_immediate_red_propagates(self, client):
        body = client.get(f"/agents/{WALLET_B}/health").json()
        assert body["alert_tier"] == "RED"
        assert body["alert_tier_code"] == 2
        assert body["immediate_red"] is True

    def test_unknown_agent_returns_404_with_structured_error(self, client):
        r = client.get(f"/agents/{WALLET_UNKNOWN}/health")
        assert r.status_code == 404
        body = r.json()
        assert body["error"] == "not_found"
        assert WALLET_UNKNOWN in body["detail"]


# =============================================================================
# /agents/{wallet}/health/{epoch}  — specific epoch
# =============================================================================

class TestAgentHealthAtEpoch:

    def test_returns_specific_epoch(self, client):
        r = client.get(f"/agents/{WALLET_A}/health/28")
        assert r.status_code == 200
        body = r.json()
        assert body["epoch"] == 28
        assert body["score"] == 851
        assert body["alert_tier"] == "YELLOW"

    def test_missing_epoch_404(self, client):
        r = client.get(f"/agents/{WALLET_A}/health/99")
        assert r.status_code == 404

    def test_epoch_below_one_rejected(self, client):
        r = client.get(f"/agents/{WALLET_A}/health/0")
        assert r.status_code == 400
        assert "epoch" in r.json()["detail"]


# =============================================================================
# /agents/{wallet}/history
# =============================================================================

class TestAgentHistory:

    def test_returns_all_epochs_newest_first(self, client):
        body = client.get(f"/agents/{WALLET_A}/history").json()
        epochs = [e["epoch"] for e in body["entries"]]
        assert epochs == [29, 28, 27]               # newest first

    def test_from_epoch_filter(self, client):
        body = client.get(
            f"/agents/{WALLET_A}/history?from_epoch=28",
        ).json()
        assert [e["epoch"] for e in body["entries"]] == [29, 28]

    def test_to_epoch_filter(self, client):
        body = client.get(
            f"/agents/{WALLET_A}/history?to_epoch=28",
        ).json()
        assert [e["epoch"] for e in body["entries"]] == [28, 27]

    def test_both_filters_combine(self, client):
        body = client.get(
            f"/agents/{WALLET_A}/history?from_epoch=28&to_epoch=28",
        ).json()
        assert [e["epoch"] for e in body["entries"]] == [28]

    def test_limit_caps_entries(self, client):
        body = client.get(f"/agents/{WALLET_A}/history?limit=1").json()
        assert len(body["entries"]) == 1
        assert body["entries"][0]["epoch"] == 29
        assert body["limit"] == 1

    @pytest.mark.parametrize("bad_limit", [0, -1, 1001])
    def test_limit_out_of_bounds_400(self, client, bad_limit):
        r = client.get(f"/agents/{WALLET_A}/history?limit={bad_limit}")
        assert r.status_code == 400

    def test_inverted_range_400(self, client):
        r = client.get(
            f"/agents/{WALLET_A}/history?from_epoch=30&to_epoch=28",
        )
        assert r.status_code == 400

    def test_unknown_agent_returns_empty_list_not_404(self, client):
        # The history endpoint is a LIST endpoint — an unknown agent is
        # a valid query with zero results, not an error.
        body = client.get(f"/agents/{WALLET_UNKNOWN}/history").json()
        assert body["entries"] == []


# =============================================================================
# /byzantine/recent
# =============================================================================

class TestByzantineRecent:

    def test_lists_recent_flags_newest_first(self, client):
        body = client.get("/byzantine/recent").json()
        assert len(body["flags"]) == 2
        # Newest epoch first.
        assert body["flags"][0]["epoch"] == 29
        assert body["flags"][1]["epoch"] == 28
        # Each flag carries the runbook-relevant fields.
        f = body["flags"][0]
        assert f["node"] == NODE_2
        assert "accused_score" in f
        assert "cluster_median" in f
        assert "deviation" in f

    def test_since_epoch_filter(self, client):
        body = client.get("/byzantine/recent?since_epoch=29").json()
        assert [f["epoch"] for f in body["flags"]] == [29]
        assert body["since_epoch"] == 29


# =============================================================================
# /byzantine/strikes
# =============================================================================

class TestByzantineStrikes:

    def test_returns_per_node_strike_summary(self, client):
        body = client.get("/byzantine/strikes").json()
        # node_id -> StrikeEntry, exactly what byzantine_flag.md greps.
        assert NODE_2 in body["summary"]
        s = body["summary"][NODE_2]
        assert s["strikes"] == 2
        assert s["flagged_epochs"] == [28, 29]
        assert s["challenged"] is False


# =============================================================================
# /byzantine/per_node — what each node revealed for one (epoch, agent)
# =============================================================================

class TestByzantinePerNode:

    def test_returns_one_row_per_node(self, client):
        body = client.get(
            f"/byzantine/per_node?epoch=28&agent={WALLET_A}",
        ).json()
        nodes = [r["node"] for r in body["reveals"]]
        # All 5 nodes have a row.
        assert nodes == list(NODE_IDS)
        # The Byzantine node's score is the odd-one-out.
        scores = {r["node"]: r["score"] for r in body["reveals"]}
        assert scores[NODE_2] == 40
        # Honest nodes cluster around 851.
        assert all(abs(scores[n] - 851) < 5
                   for n in scores if n != NODE_2)

    def test_missing_epoch_param_400(self, client):
        # epoch is REQUIRED — FastAPI returns 422 for missing query params
        # by default; we want a stable 422 for that, not 500.
        r = client.get(f"/byzantine/per_node?agent={WALLET_A}")
        assert r.status_code == 422       # FastAPI's default for missing required

    def test_epoch_below_one_400(self, client):
        r = client.get(f"/byzantine/per_node?epoch=0&agent={WALLET_A}")
        assert r.status_code == 400


# =============================================================================
# /challenges?node=...
# =============================================================================

class TestChallenges:

    def test_lists_challenges_for_accused_node(self, client):
        body = client.get(f"/challenges?node={NODE_2}").json()
        assert body["accused_node"] == NODE_2
        assert len(body["challenges"]) == 1
        c = body["challenges"][0]
        assert c["proof_type"] == 0           # Day 21: ConflictingScores
        assert c["accused_score"] == 40
        assert c["cluster_median"] == 851
        assert c["status"] == "pending"

    def test_node_with_no_challenges_returns_empty(self, client):
        body = client.get(f"/challenges?node={NODE_0}").json()
        assert body["challenges"] == []


# =============================================================================
# /health/cluster — node_down.md
# =============================================================================

class TestClusterHealth:

    def test_returns_heartbeats_and_recent_epochs(self, client):
        body = client.get("/health/cluster").json()
        # 5 heartbeats.
        assert len(body["heartbeats"]) == 5
        assert {h["node"] for h in body["heartbeats"]} == set(NODE_IDS)
        # Recent epochs newest first.
        assert [e["epoch"] for e in body["recent_epochs"]] == [29, 28]
        # Epoch 29 shows the unreachable node.
        e29 = body["recent_epochs"][0]
        assert e29["unreachable_nodes"] == [NODE_2]
        assert e29["submitted_count"] == e29["agent_count"]

    def test_limit_param(self, client):
        body = client.get("/health/cluster?limit=1").json()
        assert len(body["recent_epochs"]) == 1


# =============================================================================
# /version, /health, /metrics
# =============================================================================

class TestMetaEndpoints:

    def test_version_carries_network_and_versions(self, client):
        body = client.get("/version").json()
        assert body["network"] == "localnet"
        assert body["network_is_production"] is False
        assert body["scoring_algo_version"] == "v2.7"
        assert body["scoring_weights_version"] == "w1"
        assert body["_v"] == 2

    def test_health_liveness_is_fast(self, client):
        # The k8s/systemd liveness probe — must be fast + dependency-free.
        body = client.get("/health").json()
        assert body == {"status": "ok", "schema_version": 2}

    def test_metrics_endpoint_returns_prometheus_text(self, client):
        # Hit a route first so there's something to observe.
        client.get(f"/agents/{WALLET_A}/health")
        r = client.get("/metrics")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/plain")
        body = r.text
        # The metric names are the contract with alerts.yml.
        assert "phylanx_api_requests_total" in body
        assert "phylanx_api_request_seconds" in body
        assert "phylanx_api_is_production 0.0" in body
        assert "phylanx_api_schema_version 2.0" in body

    def test_metric_labels_use_route_template_not_literal_path(self, client):
        # Critical: per-agent cardinality would blow up the metric. The
        # label must be the template `/agents/{wallet}/health`, never
        # the literal wallet.
        wallets = [c * 44 for c in ("A", "B", "C", "D")]
        for wallet in wallets:
            client.get(f"/agents/{wallet}/health")
        body = client.get("/metrics").text
        # The template appears.
        assert '/agents/{wallet}/health' in body
        # Literal wallets DO NOT appear in metric labels.
        for wallet in wallets:
            assert f'/agents/{wallet}/health"' not in body


# =============================================================================
# Production gauge flips with the create_app argument
# =============================================================================

class TestProductionGauge:

    def test_production_gauge_set_when_is_production(
        self, score_repo, byzantine_repo, cluster_repo,
    ):
        from fastapi.testclient import TestClient
        from api.app import create_app

        app = create_app(
            score_repo=score_repo,
            byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
            network="mainnet-beta",
            is_production=True,
        )
        c = TestClient(app)
        body = c.get("/metrics").text
        assert "phylanx_api_is_production 1.0" in body
        ver = c.get("/version").json()
        assert ver["network"] == "mainnet-beta"
        assert ver["network_is_production"] is True


# =============================================================================
# OpenAPI / Swagger docs are live (the user's actual point about Day 28-30)
# =============================================================================

class TestOpenAPIDocs:

    def test_openapi_schema_served(self, client):
        r = client.get("/openapi.json")
        assert r.status_code == 200
        schema = r.json()
        # Every route is in the schema — clients can generate from this.
        assert "/agents/{wallet}/health" in schema["paths"]
        assert "/agents/{wallet}/history" in schema["paths"]
        assert "/byzantine/recent" in schema["paths"]
        assert "/byzantine/strikes" in schema["paths"]
        assert "/challenges" in schema["paths"]
        assert "/health/cluster" in schema["paths"]
        assert "/version" in schema["paths"]
        assert schema["info"]["title"] == "Phylanx V2 API"

    def test_swagger_docs_served(self, client):
        # The browser-facing surface the user pointed out.
        r = client.get("/docs")
        assert r.status_code == 200
        assert "swagger-ui" in r.text.lower()
