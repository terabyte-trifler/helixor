"""
tests/test_spof08_geyser_consensus.py — pins the SPOF-#8 mainnet floor.

The factory `build_production_geyser_config` is the only sanctioned
construction site for a production indexer. These tests assert that:

  * Mainnet refuses fewer than 3 endpoints with `SinglePointGeyserError`.
  * Mainnet refuses any `consensus_threshold < 2`.
  * Mainnet defaults `consensus_threshold` to strict majority of N.
  * Non-mainnet (devnet/localnet) accepts a single endpoint with
    `consensus_threshold = 1` and `requires_consensus = False`.
  * Endpoint specs are parsed strictly (duplicates / empties / missing
    `=` reject as `GeyserConfigError`).
  * Token lookup is name-only — the env-var NAME appears in the spec,
    the VALUE is resolved through the injected lookup, so a secret never
    appears in a spec string.

These pins make the SPOF-#8 contract auditable from outside the runner.
"""

from __future__ import annotations

import pytest

from indexer.production_config import (
    ENDPOINTS_ENV,
    MAINNET_MIN_ENDPOINTS,
    MIN_CONSENSUS_THRESHOLD,
    GeyserConfigError,
    ProductionGeyserConfig,
    SinglePointGeyserError,
    build_production_geyser_config,
)


# ── helpers ────────────────────────────────────────────────────────────────

ONE = "helius=https://h.example|HELIUS_TOKEN"
TWO = ONE + ",triton=https://t.example|TRITON_TOKEN"
THREE = TWO + ",quicknode=https://q.example|QN_TOKEN"
FOUR = THREE + ",jito=https://j.example|JITO_TOKEN"


def _tokens(**values: str):
    return lambda name: values.get(name, "")


# ── mainnet refusal ─────────────────────────────────────────────────────────

def test_mainnet_refuses_single_endpoint():
    # SPOF-#8 raison d'etre: a one-endpoint mainnet indexer is the SPOF.
    with pytest.raises(SinglePointGeyserError) as exc:
        build_production_geyser_config(
            cluster="mainnet", endpoint_spec=ONE,
            token_lookup=_tokens(),
        )
    assert "SPOF-#8" in str(exc.value)
    assert str(MAINNET_MIN_ENDPOINTS) in str(exc.value)


def test_mainnet_refuses_two_endpoints():
    # Two endpoints can detect disagreement but cannot break ties; the
    # SPOF-#8 floor is 3 (smallest N where K=2 tolerates one failure).
    with pytest.raises(SinglePointGeyserError):
        build_production_geyser_config(
            cluster="mainnet", endpoint_spec=TWO,
            token_lookup=_tokens(),
        )


def test_mainnet_beta_alias_is_treated_as_mainnet():
    with pytest.raises(SinglePointGeyserError):
        build_production_geyser_config(
            cluster="mainnet-beta", endpoint_spec=TWO,
            token_lookup=_tokens(),
        )


def test_mainnet_refuses_explicit_threshold_below_floor():
    # Even with N=3, a caller cannot opt OUT of consensus by passing K=1.
    with pytest.raises(SinglePointGeyserError):
        build_production_geyser_config(
            cluster="mainnet", endpoint_spec=THREE,
            consensus_threshold=1,
            token_lookup=_tokens(),
        )


def test_mainnet_refuses_threshold_above_n():
    # K cannot exceed N — the stream would never reach quorum.
    with pytest.raises(SinglePointGeyserError):
        build_production_geyser_config(
            cluster="mainnet", endpoint_spec=THREE,
            consensus_threshold=4,
            token_lookup=_tokens(),
        )


# ── mainnet accept ──────────────────────────────────────────────────────────

def test_mainnet_three_endpoints_defaults_to_strict_majority():
    cfg = build_production_geyser_config(
        cluster="mainnet", endpoint_spec=THREE,
        token_lookup=_tokens(HELIUS_TOKEN="h", TRITON_TOKEN="t", QN_TOKEN="q"),
    )
    assert isinstance(cfg, ProductionGeyserConfig)
    assert cfg.is_mainnet is True
    assert cfg.total_sources == 3
    assert cfg.consensus_threshold == 2  # floor(3/2) + 1
    assert cfg.requires_consensus is True
    assert cfg.endpoint_labels == ("helius", "triton", "quicknode")
    # Tokens were resolved via the lookup (NAMES in spec, VALUES via env).
    assert {e.x_token for e in cfg.endpoints} == {"h", "t", "q"}


def test_mainnet_four_endpoints_defaults_to_three():
    cfg = build_production_geyser_config(
        cluster="mainnet", endpoint_spec=FOUR,
        token_lookup=_tokens(),
    )
    # floor(4/2) + 1 = 3
    assert cfg.consensus_threshold == 3
    assert cfg.total_sources == 4


def test_mainnet_explicit_threshold_at_or_above_floor_accepted():
    cfg = build_production_geyser_config(
        cluster="mainnet", endpoint_spec=THREE,
        consensus_threshold=3,
        token_lookup=_tokens(),
    )
    assert cfg.consensus_threshold == 3  # unanimity is allowed


# ── non-mainnet pass-through ────────────────────────────────────────────────

def test_devnet_single_endpoint_is_accepted_without_consensus():
    cfg = build_production_geyser_config(
        cluster="devnet", endpoint_spec=ONE,
        token_lookup=_tokens(HELIUS_TOKEN="h"),
    )
    assert cfg.is_mainnet is False
    assert cfg.total_sources == 1
    assert cfg.consensus_threshold == 1
    assert cfg.requires_consensus is False


def test_localnet_single_endpoint_is_accepted_without_consensus():
    cfg = build_production_geyser_config(
        cluster="localnet", endpoint_spec=ONE,
        token_lookup=_tokens(),
    )
    assert cfg.is_mainnet is False
    assert cfg.consensus_threshold == 1


# ── input validation ────────────────────────────────────────────────────────

def test_missing_cluster_rejects():
    with pytest.raises(GeyserConfigError):
        build_production_geyser_config(
            cluster="", endpoint_spec=THREE, token_lookup=_tokens(),
        )


def test_missing_endpoint_spec_rejects():
    with pytest.raises(GeyserConfigError) as exc:
        build_production_geyser_config(
            cluster="mainnet", endpoint_spec="",
            token_lookup=_tokens(),
        )
    # The message must point at the env-var name so a SRE can fix it.
    assert ENDPOINTS_ENV in str(exc.value)


def test_endpoint_spec_without_equals_rejects():
    with pytest.raises(GeyserConfigError):
        build_production_geyser_config(
            cluster="devnet", endpoint_spec="helius https://example",
            token_lookup=_tokens(),
        )


def test_duplicate_endpoint_label_rejects():
    spec = "helius=https://a.example,helius=https://b.example"
    with pytest.raises(GeyserConfigError):
        build_production_geyser_config(
            cluster="devnet", endpoint_spec=spec, token_lookup=_tokens(),
        )


def test_duplicate_endpoint_url_rejects():
    # Two labels pointing at the same host defeat the entire point of
    # multi-endpoint consensus.
    spec = "a=https://h.example,b=https://h.example"
    with pytest.raises(GeyserConfigError):
        build_production_geyser_config(
            cluster="devnet", endpoint_spec=spec, token_lookup=_tokens(),
        )


def test_empty_url_rejects():
    with pytest.raises(GeyserConfigError):
        build_production_geyser_config(
            cluster="devnet", endpoint_spec="helius=",
            token_lookup=_tokens(),
        )


def test_constants_pin_the_floor():
    # Audit pin: MAINNET_MIN_ENDPOINTS and MIN_CONSENSUS_THRESHOLD are the
    # SPOF-#8 contract. Changing them changes the policy and must be
    # explicit in a PR (this test will fail on accidental relaxation).
    assert MAINNET_MIN_ENDPOINTS == 3
    assert MIN_CONSENSUS_THRESHOLD == 2
