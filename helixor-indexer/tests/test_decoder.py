"""
tests/test_decoder.py — the pure Geyser-update -> Transaction decoder.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from indexer.decoder import DecodeError, decode_transaction
from indexer.types import GeyserAccountChange, GeyserTransactionUpdate


CONF = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
AGENT = "agentXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
CP    = "counterpartyXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
PROG  = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"


def _update(*, agent_delta: int = -500_000, cp_delta: int = 500_000,
            success: bool = True) -> GeyserTransactionUpdate:
    return GeyserTransactionUpdate(
        signature="sig" + "x" * 61,
        slot=300_000_000,
        block_time=CONF,
        is_successful=success,
        fee_lamports=5000,
        compute_units=200_000,
        account_keys=(AGENT, CP, PROG),
        account_changes=(
            GeyserAccountChange(AGENT, 1_000_000_000, 1_000_000_000 + agent_delta),
            GeyserAccountChange(CP, 2_000_000_000, 2_000_000_000 + cp_delta),
        ),
        instr_program_ids=(PROG,),
        priority_fee_lamports=1000,
    )


# =============================================================================
# Core decode
# =============================================================================

class TestDecode:

    def test_decode_produces_transaction(self):
        tx = decode_transaction(_update(), AGENT)
        assert tx.signature == "sig" + "x" * 61
        assert tx.slot == 300_000_000
        assert tx.block_time == CONF

    def test_decode_copies_direct_fields(self):
        tx = decode_transaction(_update(), AGENT)
        assert tx.success is True
        assert tx.fee == 5000
        assert tx.priority_fee == 1000
        assert tx.compute_units == 200_000
        assert tx.program_ids == (PROG,)

    def test_agent_sol_change_is_its_own_delta(self):
        tx = decode_transaction(_update(agent_delta=-500_000), AGENT)
        assert tx.sol_change == -500_000

    def test_agent_gain_decoded(self):
        tx = decode_transaction(
            _update(agent_delta=750_000, cp_delta=-750_000), AGENT,
        )
        assert tx.sol_change == 750_000

    def test_failed_transaction(self):
        tx = decode_transaction(_update(success=False), AGENT)
        assert tx.success is False


# =============================================================================
# Counterparty attribution
# =============================================================================

class TestCounterpartyAttribution:

    def test_counterparty_is_opposite_mover(self):
        # Agent lost SOL → counterparty is the account that gained.
        tx = decode_transaction(
            _update(agent_delta=-500_000, cp_delta=500_000), AGENT,
        )
        assert tx.counterparty == CP

    def test_counterparty_when_agent_gains(self):
        # Agent gained → counterparty is the account that lost.
        tx = decode_transaction(
            _update(agent_delta=500_000, cp_delta=-500_000), AGENT,
        )
        assert tx.counterparty == CP

    def test_flat_agent_change_no_counterparty(self):
        tx = decode_transaction(
            _update(agent_delta=0, cp_delta=0), AGENT,
        )
        assert tx.counterparty is None

    def test_largest_mover_wins(self):
        # Two opposite-direction movers — the larger one is the counterparty.
        update = GeyserTransactionUpdate(
            signature="sig" + "y" * 61, slot=1, block_time=CONF,
            is_successful=True, fee_lamports=5000, compute_units=0,
            account_keys=(AGENT, "smallCp", "bigCp"),
            account_changes=(
                GeyserAccountChange(AGENT, 1_000_000, 1_000_000 - 900_000),
                GeyserAccountChange("smallCp", 0, 100_000),
                GeyserAccountChange("bigCp", 0, 800_000),
            ),
            instr_program_ids=(),
        )
        tx = decode_transaction(update, AGENT)
        assert tx.counterparty == "bigCp"

    def test_attribution_is_deterministic_on_ties(self):
        # Two equal-magnitude movers — the result is stable (smallest pubkey).
        update = GeyserTransactionUpdate(
            signature="sig" + "z" * 61, slot=1, block_time=CONF,
            is_successful=True, fee_lamports=0, compute_units=0,
            account_keys=(AGENT, "zzz", "aaa"),
            account_changes=(
                GeyserAccountChange(AGENT, 1_000_000, 600_000),
                GeyserAccountChange("zzz", 0, 200_000),
                GeyserAccountChange("aaa", 0, 200_000),
            ),
            instr_program_ids=(),
        )
        first = decode_transaction(update, AGENT).counterparty
        for _ in range(10):
            assert decode_transaction(update, AGENT).counterparty == first


# =============================================================================
# Error handling
# =============================================================================

class TestDecodeErrors:

    def test_agent_not_in_transaction_raises(self):
        with pytest.raises(DecodeError, match="not among"):
            decode_transaction(_update(), "someOtherAgent")

    def test_agent_with_no_balance_change(self):
        # The agent is an account key but has no recorded balance change
        # (e.g. it was only a read-only account) → sol_change 0, no error.
        update = GeyserTransactionUpdate(
            signature="sig" + "q" * 61, slot=1, block_time=CONF,
            is_successful=True, fee_lamports=0, compute_units=0,
            account_keys=(AGENT, CP),
            account_changes=(
                GeyserAccountChange(CP, 1_000_000, 1_000_000),
            ),
            instr_program_ids=(),
        )
        tx = decode_transaction(update, AGENT)
        assert tx.sol_change == 0


# =============================================================================
# Determinism
# =============================================================================

class TestDeterminism:

    def test_decode_is_deterministic(self):
        update = _update()
        first = decode_transaction(update, AGENT)
        for _ in range(20):
            assert decode_transaction(update, AGENT) == first
