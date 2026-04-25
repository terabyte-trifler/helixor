"""
tests/test_parser.py — unit tests for Helius payload parser.

Pure functions, no DB or HTTP. Fast.
"""

from __future__ import annotations

from datetime import timezone

import pytest

from indexer.parser import ParseError, parse_helius_tx


def _valid_tx(**overrides):
    """Minimal valid Helius enhanced webhook tx."""
    base = {
        "signature": "4xKtest" + "a" * 80,
        "slot":      265_000_000,
        "timestamp": 1_714_000_000,
        "type":      "TRANSFER",
        "feePayer":  "AGENTwallet" + "1" * 32,
        "fee":       5000,
        "instructions": [
            {"programId": "11111111111111111111111111111111", "accounts": []},
            {"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "accounts": []},
        ],
        "accountData": [
            {"account": "AGENTwallet" + "1" * 32, "nativeBalanceChange": -5000},
        ],
    }
    base.update(overrides)
    return base


class TestParseHeliusTx:

    def test_happy_path(self):
        p = parse_helius_tx(_valid_tx())
        assert p.signature.startswith("4xKtest")
        assert p.slot == 265_000_000
        assert p.fee_payer.startswith("AGENTwallet")
        assert p.success is True
        assert p.fee == 5000
        assert p.sol_change == -5000

    def test_block_time_is_utc(self):
        p = parse_helius_tx(_valid_tx())
        assert p.block_time.tzinfo is not None
        assert p.block_time.tzinfo == timezone.utc

    def test_failed_tx_recognised(self):
        p = parse_helius_tx(_valid_tx(type="FAILED"))
        assert p.success is False

    def test_tx_with_error_field_is_failed(self):
        p = parse_helius_tx(_valid_tx(transactionError={"InstructionError": [0, "Custom"]}))
        assert p.success is False

    def test_distinct_program_ids(self):
        tx = _valid_tx(instructions=[
            {"programId": "AAA", "accounts": []},
            {"programId": "AAA", "accounts": []},
            {"programId": "BBB", "accounts": []},
        ])
        p = parse_helius_tx(tx)
        assert p.program_ids == ["AAA", "BBB"]

    def test_handles_missing_instructions(self):
        p = parse_helius_tx(_valid_tx(instructions=None))
        assert p.program_ids == []

    def test_handles_missing_account_data(self):
        p = parse_helius_tx(_valid_tx(accountData=None))
        assert p.sol_change == 0

    def test_sums_multiple_account_entries_for_fee_payer(self):
        wallet = "AGENTwallet" + "1" * 32
        tx = _valid_tx(accountData=[
            {"account": wallet, "nativeBalanceChange": -1000},
            {"account": wallet, "nativeBalanceChange": -500},
            {"account": "OTHER" + "x" * 38, "nativeBalanceChange": -9999},  # not fee payer
        ])
        p = parse_helius_tx(tx)
        assert p.sol_change == -1500

    def test_raw_meta_preserved(self):
        tx = _valid_tx()
        p = parse_helius_tx(tx)
        assert p.raw_meta == tx

    # ── Error paths ───────────────────────────────────────────────────────────

    def test_missing_signature_raises(self):
        with pytest.raises(ParseError, match="signature"):
            parse_helius_tx(_valid_tx(signature=None))

    def test_missing_slot_raises(self):
        with pytest.raises(ParseError, match="slot"):
            parse_helius_tx(_valid_tx(slot=None))

    def test_missing_timestamp_raises(self):
        with pytest.raises(ParseError, match="timestamp"):
            parse_helius_tx(_valid_tx(timestamp=None))

    def test_zero_timestamp_raises(self):
        with pytest.raises(ParseError, match="timestamp"):
            parse_helius_tx(_valid_tx(timestamp=0))

    def test_missing_fee_payer_raises(self):
        with pytest.raises(ParseError, match="feePayer"):
            parse_helius_tx(_valid_tx(feePayer=None))
