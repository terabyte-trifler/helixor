"""
tests/oracle/test_hcr1_provider_diversity.py — HCR-1 provider diversity tests.

Pins:
  - Coarse-bucket classification of well-known providers
  - Two-bucket mainnet floor
  - Failure mode: all-Helius endpoints rejected
  - Mixed known + unknown still passes when count is >= floor
  - Distinct unknown hosts count as distinct providers
  - Report is attached to the exception
"""

from __future__ import annotations

import pytest

from oracle.provider_diversity import (
    MIN_DISTINCT_RPC_PROVIDERS,
    ProviderDiversityError,
    classify_provider,
    verify_provider_diversity,
)


# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------

def test_mainnet_floor_is_two_distinct_providers():
    assert MIN_DISTINCT_RPC_PROVIDERS == 2


# ----------------------------------------------------------------------------
# Classification
# ----------------------------------------------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("https://mainnet.helius-rpc.com",                 "helius"),
    ("https://rpc.helius.xyz/?api-key=abc",            "helius"),
    ("https://solana-mainnet.rpcpool.com",             "triton"),
    ("https://rpc.triton.one",                         "triton"),
    ("https://wandering-solitary.solana-mainnet.quiknode.pro/aaa/", "quicknode"),
    ("https://solana-mainnet.g.alchemy.com/v2/key",    "alchemy"),
    ("https://rpc.ankr.com/solana",                    "ankr"),
    ("https://svc.blockdaemon.com/solana",             "blockdaemon"),
    ("https://nd-000-000-000.p2pify.chainstack.com",   "chainstack"),
    ("https://solana-mainnet.api.syndica.io/api-key",  "syndica"),
    ("https://api.mainnet-beta.solana.com",            "solana-labs"),
])
def test_well_known_providers_classified(url: str, expected: str):
    assert classify_provider(url) == expected


def test_unknown_host_bucketed_under_host():
    assert classify_provider("https://my-private-validator.io:8899").startswith(
        "unknown:my-private-validator.io"
    )


def test_unparseable_url_raises_value_error():
    with pytest.raises(ValueError, match="no host"):
        classify_provider("not a url")


def test_classification_is_case_insensitive():
    assert classify_provider("https://MAINNET.HELIUS-RPC.COM") == "helius"


# ----------------------------------------------------------------------------
# Empty / invalid inputs
# ----------------------------------------------------------------------------

def test_empty_endpoints_rejected():
    with pytest.raises(ProviderDiversityError, match="non-empty"):
        verify_provider_diversity([])


def test_zero_min_distinct_rejected():
    with pytest.raises(ProviderDiversityError, match=">= 1"):
        verify_provider_diversity(
            ["https://mainnet.helius-rpc.com"],
            min_distinct=0,
        )


# ----------------------------------------------------------------------------
# Diversity gate — happy path
# ----------------------------------------------------------------------------

def test_two_distinct_providers_passes():
    report = verify_provider_diversity([
        "https://mainnet.helius-rpc.com",
        "https://solana-mainnet.rpcpool.com",
    ])
    assert report.is_diverse
    assert report.distinct_count == 2
    assert report.providers == ("helius", "triton")


def test_three_distinct_providers_passes():
    report = verify_provider_diversity([
        "https://mainnet.helius-rpc.com",
        "https://solana-mainnet.rpcpool.com",
        "https://wandering-solitary.solana-mainnet.quiknode.pro/k/",
    ])
    assert report.is_diverse
    assert report.distinct_count == 3


def test_two_unknown_hosts_count_as_distinct_providers():
    # Self-hosted validators legitimately contribute to diversity.
    report = verify_provider_diversity([
        "https://validator-a.example.com",
        "https://validator-b.example.com",
    ])
    assert report.is_diverse
    assert report.distinct_count == 2
    assert all(p.startswith("unknown:") for p in report.providers)


# ----------------------------------------------------------------------------
# Diversity gate — failure mode
# ----------------------------------------------------------------------------

def test_two_helius_endpoints_rejected():
    with pytest.raises(ProviderDiversityError, match="HCR-1") as excinfo:
        verify_provider_diversity([
            "https://mainnet.helius-rpc.com",
            "https://rpc.helius.xyz/?api-key=abc",
        ])
    # Report attached to the exception so operators can see WHICH endpoints
    # over-concentrated.
    report = excinfo.value.report
    assert report.distinct_count == 1
    assert report.providers == ("helius", "helius")
    assert not report.is_diverse


def test_three_quicknode_endpoints_rejected():
    with pytest.raises(ProviderDiversityError):
        verify_provider_diversity([
            "https://node-1.solana-mainnet.quiknode.pro/aa",
            "https://node-2.solana-mainnet.quiknode.pro/bb",
            "https://node-3.solana-mainnet.quiknode.pro/cc",
        ])


def test_same_hostname_collapses_to_one_provider():
    # Two distinct URLs sharing a private hostname (e.g. paths only)
    # are ONE provider — HCR-1's whole point.
    with pytest.raises(ProviderDiversityError):
        verify_provider_diversity([
            "https://validator.example.com/path-a",
            "https://validator.example.com/path-b",
        ])


# ----------------------------------------------------------------------------
# Threshold tuning
# ----------------------------------------------------------------------------

def test_min_distinct_three_requires_three_distinct():
    with pytest.raises(ProviderDiversityError):
        verify_provider_diversity(
            [
                "https://mainnet.helius-rpc.com",
                "https://solana-mainnet.rpcpool.com",
            ],
            min_distinct=3,
        )


def test_min_distinct_one_is_a_smoke_floor():
    # Pathological but legal: K=1 means "any endpoint is enough", useful
    # for devnet-only configs. HCR-1 documents that mainnet MUST use the
    # default floor of 2.
    report = verify_provider_diversity(
        ["https://mainnet.helius-rpc.com"], min_distinct=1,
    )
    assert report.is_diverse
