"""
tests/oracle/test_network_guard.py — Day-30 mainnet refusal gate.

Pins the safety belt that prevents any Helixor entrypoint from starting
against mainnet without an explicit opt-in.
"""

from __future__ import annotations

import pytest

from oracle.network_guard import (
    DEFAULT_NETWORK,
    NETWORK_DEVNET,
    NETWORK_LOCALNET,
    NETWORK_MAINNET_BETA,
    NETWORK_TESTNET,
    PRODUCTION_NETWORKS,
    ProductionRefused,
    UnsupportedNetwork,
    current_network,
    enforce_network_guard,
    evaluate,
    opted_in_to_mainnet,
    override_network,
)


def test_oracle_node_refuses_production_plaintext_grpc(monkeypatch):
    """
    Mainnet opt-in alone is not enough for oracle peer transport: production
    gRPC must have mTLS material. This prevents a 5-node cluster from
    accidentally starting on plaintext sockets.
    """
    from oracle.cluster.run_cluster_node import main

    monkeypatch.setenv("HELIXOR_NETWORK", NETWORK_MAINNET_BETA)
    monkeypatch.setenv("HELIXOR_MAINNET_OK", "1")
    monkeypatch.delenv("HELIXOR_GRPC_TLS_CERT", raising=False)
    monkeypatch.delenv("HELIXOR_GRPC_TLS_KEY", raising=False)
    monkeypatch.delenv("HELIXOR_GRPC_TLS_CA_CERT", raising=False)

    rc = main(["--node-id", "oracle-node-0", "--port", "50051"])
    assert rc == 2


# =============================================================================
# Defaults — a fresh process refuses anything risky
# =============================================================================

class TestDefaults:

    def test_default_network_is_localnet(self):
        """Unset env -> localnet, the safest default."""
        assert DEFAULT_NETWORK == NETWORK_LOCALNET

    def test_production_network_set_is_mainnet_only(self):
        # The production set must NOT contain devnet or testnet — those
        # are public clusters but not gated. Only mainnet refuses.
        assert PRODUCTION_NETWORKS == frozenset({NETWORK_MAINNET_BETA})

    def test_no_opt_in_by_default(self):
        with override_network(NETWORK_LOCALNET):
            assert opted_in_to_mainnet() is False


# =============================================================================
# Verdict — non-production networks pass cleanly
# =============================================================================

class TestNonProductionPasses:

    @pytest.mark.parametrize("net", [
        NETWORK_LOCALNET, NETWORK_DEVNET, NETWORK_TESTNET,
    ])
    def test_non_production_network_allowed(self, net):
        with override_network(net):
            verdict = enforce_network_guard(service="ut")
            assert verdict.network == net
            assert verdict.is_production is False
            assert verdict.must_refuse is False


# =============================================================================
# Mainnet refusal — THE core property
# =============================================================================

class TestMainnetRefusal:

    def test_mainnet_without_opt_in_is_refused(self):
        """The done-when of Day 30: mainnet starts without opt-in fail."""
        with override_network(NETWORK_MAINNET_BETA, mainnet_ok=False):
            with pytest.raises(ProductionRefused) as exc:
                enforce_network_guard(service="ut")
            # The error message must guide the operator to the runbook.
            assert "REFUSING" in str(exc.value)
            assert "HELIXOR_MAINNET_OK" in str(exc.value)

    def test_mainnet_with_opt_in_is_allowed(self):
        with override_network(NETWORK_MAINNET_BETA, mainnet_ok=True):
            verdict = enforce_network_guard(service="ut")
            assert verdict.network == NETWORK_MAINNET_BETA
            assert verdict.is_production is True
            assert verdict.opted_in is True
            assert verdict.must_refuse is False

    def test_evaluate_does_not_raise_on_mainnet(self):
        # `evaluate()` is the introspection path — it returns the verdict
        # rather than raising, so callers can inspect without committing
        # to a guard check. Only `enforce_network_guard` raises.
        with override_network(NETWORK_MAINNET_BETA):
            verdict = evaluate()
            assert verdict.must_refuse is True


# =============================================================================
# Unknown networks are refused with a clear error
# =============================================================================

class TestUnsupportedNetwork:

    def test_unknown_network_refused(self):
        with override_network("some-third-party-cluster"):
            with pytest.raises(UnsupportedNetwork) as exc:
                enforce_network_guard(service="ut")
            assert "not in" in str(exc.value)


# =============================================================================
# override_network restores prior values
# =============================================================================

class TestOverrideRestores:

    def test_env_restored_after_block(self):
        import os
        prev = os.environ.get("HELIXOR_NETWORK")
        with override_network(NETWORK_MAINNET_BETA, mainnet_ok=True):
            assert os.environ["HELIXOR_NETWORK"] == NETWORK_MAINNET_BETA
            assert os.environ["HELIXOR_MAINNET_OK"] == "1"
        assert os.environ.get("HELIXOR_NETWORK") == prev
        assert "HELIXOR_MAINNET_OK" not in os.environ

    def test_env_restored_after_exception(self):
        import os
        prev = os.environ.get("HELIXOR_NETWORK")
        with pytest.raises(RuntimeError, match="injected"):
            with override_network(NETWORK_MAINNET_BETA):
                raise RuntimeError("injected")
        assert os.environ.get("HELIXOR_NETWORK") == prev


# =============================================================================
# Service label appears in the log path (smoke)
# =============================================================================

class TestServiceLabel:

    def test_service_name_in_refusal_message(self):
        with override_network(NETWORK_MAINNET_BETA):
            with pytest.raises(ProductionRefused) as exc:
                enforce_network_guard(service="oracle-node:0")
            assert "oracle-node:0" in str(exc.value)
