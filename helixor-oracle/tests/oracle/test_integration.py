"""
tests/oracle/test_integration.py — END-TO-END integration test.

WHAT THIS DOES
--------------
1. Boots solana-test-validator on a free port (or uses an external one via env).
2. Computes a deterministic v2 baseline in Python (Day 2 engine).
3. Calls submit_baseline_commitment() — the production code path.
4. Reads the AgentRegistration PDA back from chain.
5. Asserts: on-chain baseline_hash == Python stats_hash, BYTE FOR BYTE.

REQUIREMENTS
------------
This test needs the program deployed at HELIXOR_PROGRAM_ID on the validator,
the OracleConfig PDA initialised, and an AgentRegistration PDA already at v2
layout (created by register_agent or already migrated). In CI, the harness
script `tests/oracle/_localnet.py` (separate) handles those preconditions.

WHEN TO SKIP
------------
This test SKIPS if the required env vars are absent — so unit-test runs
(no validator) stay green. The full integration runs in a dedicated CI job.

Environment:
    HELIXOR_INTEGRATION    = 1            opt-in flag
    HELIXOR_PROGRAM_ID                    deployed program ID
    SOLANA_RPC_URL                        e.g. http://127.0.0.1:8899
    ORACLE_KEYPAIR_PATH                   the oracle authority keypair
    HELIXOR_TEST_AGENT_PUBKEY             a registered, v2-layout agent
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

# This module ONLY imports the heavy on-chain bits if integration is enabled —
# keeps unit-test collection fast and dependency-free.
INTEGRATION = os.environ.get("HELIXOR_INTEGRATION") == "1"

pytestmark = pytest.mark.skipif(
    not INTEGRATION,
    reason="set HELIXOR_INTEGRATION=1 + the validator env vars to run",
)


@pytest.mark.asyncio
async def test_commit_baseline_round_trip_onchain():
    """
    The Day-3 done-when: a baseline hash computed in Python is readable on-chain,
    byte-matching.
    """
    from solders.pubkey import Pubkey

    from baseline import compute_baseline
    from features import ExtractionWindow, Transaction
    from oracle import CommitConfig, submit_baseline_commitment

    config       = CommitConfig.from_env()
    agent_wallet = os.environ["HELIXOR_TEST_AGENT_PUBKEY"]

    # 1. Build a deterministic transaction history in-memory.
    end    = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    window = ExtractionWindow.ending_at(end, days=30)
    txs    = _make_test_txs(end=end)

    # 2. Compute the baseline.
    baseline = compute_baseline(agent_wallet, txs, window, computed_at=end)
    assert baseline.is_compatible_with_current_engine()
    assert len(baseline.stats_hash) == 64

    # 3. Submit.
    result = await submit_baseline_commitment(config, baseline)

    # 4. Read-back assertion is INSIDE submit_baseline_commitment, but verify
    #    again here independently using a fresh fetch.
    from oracle import (
        decode_agent_registration_v2,
        derive_agent_registration_pda,
    )
    from solana.rpc.async_api import AsyncClient
    from solana.rpc.commitment import Confirmed

    agent_pda, _ = derive_agent_registration_pda(
        config.program_id, Pubkey.from_string(agent_wallet),
    )
    async with AsyncClient(config.rpc_url) as client:
        resp = await client.get_account_info(agent_pda, commitment=Confirmed)
        assert resp.value is not None
        decoded = decode_agent_registration_v2(bytes(resp.value.data))

    # ── THE DAY-3 DONE-WHEN ──────────────────────────────────────────────────
    from baseline import stats_hash_to_bytes
    expected_bytes = stats_hash_to_bytes(baseline.stats_hash)
    assert decoded.baseline_hash == expected_bytes, (
        "on-chain hash does NOT byte-match the Python stats_hash"
    )
    assert decoded.baseline_committed is True
    assert decoded.baseline_algo_version == baseline.baseline_algo_version
    assert decoded.commit_nonce == result.commit_nonce


@pytest.mark.asyncio
async def test_idempotent_resubmit_skips_when_hash_unchanged():
    """Re-submitting the same baseline must NOT send a redundant transaction."""
    from datetime import datetime, timezone

    from baseline import compute_baseline
    from features import ExtractionWindow
    from oracle import CommitConfig, submit_baseline_commitment

    config       = CommitConfig.from_env()
    agent_wallet = os.environ["HELIXOR_TEST_AGENT_PUBKEY"]
    end    = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    window = ExtractionWindow.ending_at(end, days=30)
    txs    = _make_test_txs(end=end)
    baseline = compute_baseline(agent_wallet, txs, window, computed_at=end)

    # First submit (assumed to have run by the previous test; safe to repeat).
    r1 = await submit_baseline_commitment(config, baseline)

    # Second submit with the same baseline — should detect "already on-chain"
    # and return an empty tx_signature.
    r2 = await submit_baseline_commitment(config, baseline)
    assert r2.tx_signature == ""        # no transaction sent
    assert r2.commit_nonce == r1.commit_nonce  # nonce did not advance


@pytest.mark.asyncio
async def test_nonce_advances_on_real_change():
    """When the baseline content changes, the nonce must strictly increase."""
    from datetime import datetime, timezone

    from baseline import compute_baseline
    from features import ExtractionWindow
    from oracle import CommitConfig, submit_baseline_commitment

    config       = CommitConfig.from_env()
    agent_wallet = os.environ["HELIXOR_TEST_AGENT_PUBKEY"]
    end    = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    window = ExtractionWindow.ending_at(end, days=30)

    txs_a = _make_test_txs(end=end, success_rate=0.95)
    txs_b = _make_test_txs(end=end, success_rate=0.50)

    b_a = compute_baseline(agent_wallet, txs_a, window, computed_at=end)
    b_b = compute_baseline(agent_wallet, txs_b, window, computed_at=end)
    assert b_a.stats_hash != b_b.stats_hash  # sanity: different content

    r_a = await submit_baseline_commitment(config, b_a)
    r_b = await submit_baseline_commitment(config, b_b)
    assert r_b.commit_nonce > r_a.commit_nonce


# =============================================================================
# Helpers
# =============================================================================

def _make_test_txs(end, *, days: int = 30, txs_per_day: int = 5, success_rate: float = 0.95):
    """Deterministic transaction set — same shape as Day 2's conftest."""
    from datetime import timedelta

    from features import Transaction

    PROG_SWAP = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
    txs = []
    fail_every = max(2, int(round(1.0 / max(1e-9, 1.0 - success_rate))))
    for day in range(days):
        for k in range(txs_per_day):
            idx = day * txs_per_day + k
            txs.append(Transaction(
                signature=f"S{idx:08d}".ljust(64, "x"),
                slot=100_000_000 + idx,
                block_time=end - timedelta(hours=day * 24 + k * 2 + 1.0),
                success=(idx % fail_every) != 0,
                program_ids=(PROG_SWAP,),
                sol_change=1_000_000 if k % 2 == 0 else -400_000,
                fee=5000,
                priority_fee=1000 if k % 3 == 0 else 0,
                compute_units=200_000,
                counterparty=f"cp{idx % 7}",
            ))
    return txs
