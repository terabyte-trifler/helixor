"""
tests/oracle/test_ta8_multi_rpc.py — TA-8 multi-RPC consensus tests.

Pins:
  - Strict-majority default threshold (floor(N/2)+1)
  - 3-endpoint quorum tolerates 1 disagreement
  - Mixed errors + values still produce consensus if quorum reached
  - Exceeded threshold → RpcDivergenceError with full per-endpoint report
  - Mainnet floor constants pinned
"""

from __future__ import annotations

import pytest

from oracle.multi_rpc import (
    MAINNET_MIN_RPC_ENDPOINTS,
    MIN_RPC_CONSENSUS_THRESHOLD,
    MultiRpcConfigError,
    MultiRpcConsensus,
    RpcDivergenceError,
)


# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------

def test_mainnet_floor_is_three_endpoints():
    assert MAINNET_MIN_RPC_ENDPOINTS == 3


def test_min_consensus_threshold_is_two():
    assert MIN_RPC_CONSENSUS_THRESHOLD == 2


# ----------------------------------------------------------------------------
# Constructor invariants
# ----------------------------------------------------------------------------

def test_empty_endpoints_rejected():
    with pytest.raises(MultiRpcConfigError, match="non-empty"):
        MultiRpcConsensus(endpoints=[])


def test_duplicate_endpoints_rejected():
    with pytest.raises(MultiRpcConfigError, match="duplicate"):
        MultiRpcConsensus(endpoints=["helius", "helius", "triton"])


def test_threshold_exceeding_endpoint_count_rejected():
    with pytest.raises(MultiRpcConfigError, match="cannot exceed"):
        MultiRpcConsensus(endpoints=["helius", "triton"], min_agreements=3)


def test_default_threshold_is_strict_majority():
    # N=3 → K=2; N=5 → K=3.
    c3 = MultiRpcConsensus(endpoints=["a", "b", "c"])
    assert c3.min_agreements == 2
    c5 = MultiRpcConsensus(endpoints=["a", "b", "c", "d", "e"])
    assert c5.min_agreements == 3


# ----------------------------------------------------------------------------
# Happy path — all agree
# ----------------------------------------------------------------------------

def test_three_endpoints_unanimous_returns_value():
    c = MultiRpcConsensus(endpoints=["a", "b", "c"])
    fetched = {"a": 12345, "b": 12345, "c": 12345}
    report = c.fetch(fetched.__getitem__)
    assert report.reached_consensus
    assert report.consensus_value == 12345
    assert report.agreeing_count == 3


# ----------------------------------------------------------------------------
# Quorum tolerates 1 dissenter
# ----------------------------------------------------------------------------

def test_three_endpoints_one_dissenter_still_produces_consensus():
    c = MultiRpcConsensus(endpoints=["a", "b", "c"])
    fetched = {"a": 100, "b": 100, "c": 999}
    report = c.fetch(fetched.__getitem__)
    assert report.consensus_value == 100
    assert report.agreeing_count == 2
    assert report.responses["c"] == 999  # dissenter still recorded


# ----------------------------------------------------------------------------
# Quorum cannot be reached → RpcDivergenceError
# ----------------------------------------------------------------------------

def test_split_three_way_raises_divergence():
    c = MultiRpcConsensus(endpoints=["a", "b", "c"])
    fetched = {"a": 1, "b": 2, "c": 3}
    with pytest.raises(RpcDivergenceError) as excinfo:
        c.fetch(fetched.__getitem__)
    assert "TA-8" in str(excinfo.value)
    # Report still attached to the exception:
    report = excinfo.value.report
    assert report.consensus_value is None
    assert report.agreeing_count == 0
    assert set(report.responses) == {"a", "b", "c"}


# ----------------------------------------------------------------------------
# Endpoint errors handled in isolation
# ----------------------------------------------------------------------------

def test_one_endpoint_error_still_consensus_via_other_two():
    c = MultiRpcConsensus(endpoints=["a", "b", "c"])

    def fetcher(label):
        if label == "c":
            raise RuntimeError("MITM detected")
        return 200

    report = c.fetch(fetcher)
    assert report.consensus_value == 200
    assert report.agreeing_count == 2
    assert report.errors["c"].startswith("RuntimeError: MITM detected")


def test_all_endpoints_error_raises_divergence():
    c = MultiRpcConsensus(endpoints=["a", "b", "c"])

    def fetcher(label):
        raise ConnectionError(f"{label} unreachable")

    with pytest.raises(RpcDivergenceError) as excinfo:
        c.fetch(fetcher)
    assert all(v is None for v in excinfo.value.report.responses.values())
    assert all(
        err.startswith("ConnectionError")
        for err in excinfo.value.report.errors.values()
    )


# ----------------------------------------------------------------------------
# Two endpoints — degenerate but legal (with K=2 specified explicitly)
# ----------------------------------------------------------------------------

def test_two_endpoints_with_both_required():
    c = MultiRpcConsensus(endpoints=["a", "b"], min_agreements=2)
    assert c.fetch({"a": 5, "b": 5}.__getitem__).consensus_value == 5
    with pytest.raises(RpcDivergenceError):
        c.fetch({"a": 5, "b": 6}.__getitem__)
