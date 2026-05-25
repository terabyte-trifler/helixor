"""
tests/test_vuln24_flag_obfuscation.py — VULN-24 mitigation #4.

The wire shape of GET /agents/{wallet}/health MUST NOT echo the raw
detection bitmask. These tests pin the obfuscation contract: opaque
token + popcount, no raw `flags` field, deterministic within an
(agent, epoch) tuple, but not reversible across tuples.
"""

from __future__ import annotations

import pytest

from api.flag_obfuscation import (
    FLAG_OBFUSCATION_ALGO_VERSION,
    TOKEN_HEX_CHARS,
    compute_flag_token,
    popcount,
)
from tests.conftest import WALLET_A, WALLET_B


# =============================================================================
# compute_flag_token — pure helper
# =============================================================================

class TestComputeFlagToken:

    def test_deterministic_same_inputs(self):
        a = compute_flag_token(flags=0x42, agent_wallet=WALLET_A, epoch=29)
        b = compute_flag_token(flags=0x42, agent_wallet=WALLET_A, epoch=29)
        assert a == b

    def test_token_width_is_pinned(self):
        tok = compute_flag_token(flags=0x42, agent_wallet=WALLET_A, epoch=29)
        assert len(tok) == TOKEN_HEX_CHARS
        # Must be valid hex.
        int(tok, 16)

    def test_token_changes_when_flags_change(self):
        a = compute_flag_token(flags=0x42, agent_wallet=WALLET_A, epoch=29)
        b = compute_flag_token(flags=0x43, agent_wallet=WALLET_A, epoch=29)
        assert a != b

    def test_same_flags_different_agents_produce_different_tokens(self):
        # An observer cannot equate tokens across agents to infer
        # "these two agents had the same detectors fire".
        a = compute_flag_token(flags=0xFF, agent_wallet=WALLET_A, epoch=29)
        b = compute_flag_token(flags=0xFF, agent_wallet=WALLET_B, epoch=29)
        assert a != b

    def test_same_flags_different_epochs_produce_different_tokens(self):
        # The per-epoch read-then-craft feedback loop is the attack —
        # cross-epoch identity must NOT be readable from the token.
        a = compute_flag_token(flags=0xFF, agent_wallet=WALLET_A, epoch=28)
        b = compute_flag_token(flags=0xFF, agent_wallet=WALLET_A, epoch=29)
        assert a != b

    def test_zero_flags_is_still_a_valid_token(self):
        # An all-zero flag set is a normal case for a clean agent and
        # MUST hash like any other — never return an empty string.
        tok = compute_flag_token(flags=0x00, agent_wallet=WALLET_A, epoch=29)
        assert len(tok) == TOKEN_HEX_CHARS

    def test_rejects_negative_flags(self):
        with pytest.raises(ValueError):
            compute_flag_token(flags=-1, agent_wallet=WALLET_A, epoch=29)

    def test_rejects_flags_above_u32(self):
        with pytest.raises(ValueError):
            compute_flag_token(
                flags=0x1_0000_0000, agent_wallet=WALLET_A, epoch=29,
            )

    def test_rejects_bool_flags(self):
        with pytest.raises(TypeError):
            compute_flag_token(flags=True, agent_wallet=WALLET_A, epoch=29)

    def test_rejects_empty_wallet(self):
        with pytest.raises(ValueError):
            compute_flag_token(flags=0x42, agent_wallet="", epoch=29)

    def test_rejects_negative_epoch(self):
        with pytest.raises(ValueError):
            compute_flag_token(flags=0x42, agent_wallet=WALLET_A, epoch=-1)


# =============================================================================
# popcount — diagnostic-only count
# =============================================================================

class TestPopcount:

    def test_zero(self):
        assert popcount(0x00) == 0

    def test_single_bit(self):
        assert popcount(0x01) == 1
        assert popcount(1 << 31) == 1

    def test_multiple_bits(self):
        assert popcount(0xFF) == 8
        assert popcount(0x42) == 2

    def test_max_u32(self):
        assert popcount(0xFFFFFFFF) == 32

    def test_rejects_negative(self):
        with pytest.raises(ValueError):
            popcount(-1)

    def test_rejects_above_u32(self):
        with pytest.raises(ValueError):
            popcount(0x1_0000_0000)

    def test_rejects_bool(self):
        with pytest.raises(TypeError):
            popcount(True)


# =============================================================================
# /agents/{wallet}/health — the wire contract
# =============================================================================

class TestHealthEndpointObfuscation:

    def test_raw_flags_field_not_in_response(self, client):
        # The single most important assertion in this file: the raw
        # `flags` integer must NEVER appear on the wire. If a future
        # change re-adds it, this test fails — VULN-24 mitigation #4
        # is then broken.
        body = client.get(f"/agents/{WALLET_A}/health").json()
        assert "flags" not in body

    def test_response_carries_obfuscated_token_and_count(self, client):
        body = client.get(f"/agents/{WALLET_A}/health").json()
        assert "flag_set_token" in body
        assert "flag_count"     in body
        # Token width matches the helper.
        assert len(body["flag_set_token"]) == TOKEN_HEX_CHARS
        # Valid hex.
        int(body["flag_set_token"], 16)

    def test_flag_count_matches_popcount(self, client):
        # WALLET_A @ epoch 29 has flags=0x00 in the seed → count = 0.
        body = client.get(f"/agents/{WALLET_A}/health").json()
        assert body["flag_count"] == 0
        # WALLET_B @ epoch 29 has flags=0xff in the seed → count = 8.
        body = client.get(f"/agents/{WALLET_B}/health").json()
        assert body["flag_count"] == 8

    def test_token_changes_across_epochs(self, client):
        # WALLET_A has flags 0x00, 0x42, 0x00 across epochs 27/28/29.
        # The 0x00 epochs MUST emit different tokens — otherwise an
        # attacker could read "same token => same flags" across time.
        body_27 = client.get(f"/agents/{WALLET_A}/health/27").json()
        body_29 = client.get(f"/agents/{WALLET_A}/health/29").json()
        assert body_27["flag_set_token"] != body_29["flag_set_token"]

    def test_token_same_for_same_request_repeated(self, client):
        # Same (agent, epoch) tuple → same token across replicas /
        # repeated requests. Otherwise the cache key is useless.
        a = client.get(f"/agents/{WALLET_A}/health/29").json()
        b = client.get(f"/agents/{WALLET_A}/health/29").json()
        assert a["flag_set_token"] == b["flag_set_token"]

    def test_token_differs_across_agents_same_epoch(self, client):
        # WALLET_A @ 29 has flags=0x00; WALLET_B @ 29 has flags=0xff.
        # Even with identical flags the tokens would differ; with
        # different flags they certainly do.
        a = client.get(f"/agents/{WALLET_A}/health/29").json()
        b = client.get(f"/agents/{WALLET_B}/health/29").json()
        assert a["flag_set_token"] != b["flag_set_token"]

    def test_immediate_red_still_exposed(self, client):
        # The ONE flag-derived signal a consumer must act on stays
        # explicit. VULN-24 does not hide red alerts — only the
        # internal detector identity behind them.
        body = client.get(f"/agents/{WALLET_B}/health").json()
        assert body["immediate_red"] is True

    def test_algo_version_constant_is_at_least_one(self):
        # If we ever bump this without intending to, the wire-token
        # of every prior cert silently changes. This is a tripwire,
        # not a functional check.
        assert FLAG_OBFUSCATION_ALGO_VERSION >= 1
