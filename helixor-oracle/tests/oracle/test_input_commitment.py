"""
tests/oracle/test_input_commitment.py — AW-01 input-provenance commitment.

The pure commitment primitive is the load-bearing piece for trust-transitivity
closure: every later layer (commit-reveal binding, cross-node agreement,
on-chain digest, SDK verifier) recomputes this exact hash and rejects on
mismatch. These tests pin the canonical form, determinism, sort-invariance,
and collision discipline.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from features import ExtractionWindow, Transaction
from oracle.cluster.input_commitment import (
    COMMITMENT_BYTES,
    INPUT_COMMITMENT_VERSION,
    SlotAnchor,
    commitments_agree,
    compute_input_commitment,
)


# =============================================================================
# Test fixtures
# =============================================================================

UTC = timezone.utc
T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _tx(sig: str, slot: int, *, sol_change: int = 1_000, success: bool = True,
        counterparty: str | None = None) -> Transaction:
    return Transaction(
        signature=sig, slot=slot,
        block_time=T0 + timedelta(seconds=slot),
        success=success,
        program_ids=("ProgA", "ProgB"),
        sol_change=sol_change, fee=5_000,
        priority_fee=100, compute_units=200_000,
        counterparty=counterparty,
    )


def _window(start_offset_days: float, end_offset_days: float) -> ExtractionWindow:
    return ExtractionWindow(
        start=T0 + timedelta(days=start_offset_days),
        end=T0 + timedelta(days=end_offset_days),
    )


WALLET = "agent1111111111111111111111111111111111111111"
BASELINE_HASH = b"\x42" * 32
SLOT_ANCHOR = SlotAnchor(slot=250_000_000, block_hash=b"\x99" * 32)

BASELINE_WIN = _window(-7, 0)
CURRENT_WIN = _window(0, 1)
BASELINE_TXS = (_tx("sigB1", 100), _tx("sigB2", 200))
CURRENT_TXS = (_tx("sigC1", 300), _tx("sigC2", 400))


# =============================================================================
# Determinism + shape
# =============================================================================

class TestCommitmentShape:

    def test_returns_32_bytes(self):
        commitment = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        assert len(commitment) == COMMITMENT_BYTES == 32

    def test_deterministic_same_inputs_same_output(self):
        c1 = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        c2 = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        assert c1 == c2

    def test_baseline_hash_must_be_32_bytes(self):
        with pytest.raises(ValueError, match="32 bytes"):
            compute_input_commitment(
                WALLET, BASELINE_WIN, CURRENT_WIN,
                BASELINE_TXS, CURRENT_TXS, baseline_hash=b"\x42" * 31,
                slot_anchor=SLOT_ANCHOR,
            )

    def test_empty_wallet_rejected(self):
        with pytest.raises(ValueError, match="agent_wallet"):
            compute_input_commitment(
                "", BASELINE_WIN, CURRENT_WIN,
                BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
                slot_anchor=SLOT_ANCHOR,
            )


# =============================================================================
# Sort-invariance: input ordering doesn't change the commitment
# =============================================================================

class TestSortInvariance:
    """Kafka can replay transactions in any order; the commitment must not
    depend on that order."""

    def test_reversed_txs_yield_same_commitment(self):
        c_forward = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        c_reverse = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            tuple(reversed(BASELINE_TXS)), tuple(reversed(CURRENT_TXS)),
            BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        assert c_forward == c_reverse

    def test_same_slot_different_signature_distinguished_by_sig(self):
        # Same slot is sorted by signature next; two tx sets that differ
        # only in signature must still hit deterministic order.
        txs_a = (_tx("aaaa", 100), _tx("bbbb", 100))
        txs_b = (_tx("bbbb", 100), _tx("aaaa", 100))
        c_a = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            txs_a, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        c_b = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            txs_b, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        assert c_a == c_b


# =============================================================================
# Distinct-input -> distinct-commitment (poison detection)
# =============================================================================

class TestPoisonDetection:
    """Every meaningful poisoning at the upstream layer must yield a
    different commitment so the cross-node check catches it."""

    def test_changing_a_single_tx_sol_change_changes_commitment(self):
        # An attacker that flips the sol_change of one tx — must show.
        base = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        poisoned = (_tx("sigC1", 300, sol_change=999_999), _tx("sigC2", 400))
        attacked = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, poisoned, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        assert base != attacked

    def test_inserting_a_fake_tx_changes_commitment(self):
        base = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        injected = CURRENT_TXS + (_tx("FAKE", 999),)
        attacked = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, injected, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        assert base != attacked

    def test_dropping_a_tx_changes_commitment(self):
        base = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        truncated = CURRENT_TXS[:1]
        attacked = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, truncated, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        assert base != attacked

    def test_swapping_baseline_and_current_changes_commitment(self):
        # A cross-period swap (treating current as baseline) — must show.
        base = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        swapped = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            CURRENT_TXS, BASELINE_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        assert base != swapped

    def test_different_wallet_yields_different_commitment(self):
        c_a = compute_input_commitment(
            "agentA", BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        c_b = compute_input_commitment(
            "agentB", BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        assert c_a != c_b

    def test_different_baseline_hash_yields_different_commitment(self):
        c1 = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, b"\x01" * 32,
            slot_anchor=SLOT_ANCHOR,
        )
        c2 = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, b"\x02" * 32,
            slot_anchor=SLOT_ANCHOR,
        )
        assert c1 != c2

    def test_different_window_yields_different_commitment(self):
        c1 = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        # Shift current window by one day — same txs, different windows.
        shifted = _window(1, 2)
        c2 = compute_input_commitment(
            WALLET, BASELINE_WIN, shifted,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        assert c1 != c2

    def test_optional_counterparty_present_vs_absent_differs(self):
        # An attacker that strips the counterparty field — must show.
        with_cp = (_tx("sigC1", 300, counterparty="ctr"), _tx("sigC2", 400))
        without_cp = (_tx("sigC1", 300, counterparty=None), _tx("sigC2", 400))
        c1 = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, with_cp, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        c2 = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, without_cp, BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        assert c1 != c2

    def test_different_slot_anchor_changes_commitment(self):
        # AW-01-EXT: a different SlotAnchor (same upstream inputs) must
        # yield a different commitment so an attacker that poisons every
        # upstream RPC the cluster reads from STILL cannot match a slot
        # Solana itself recorded.
        c1 = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SlotAnchor(slot=250_000_000, block_hash=b"\x99" * 32),
        )
        # Different slot.
        c2 = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SlotAnchor(slot=250_000_001, block_hash=b"\x99" * 32),
        )
        assert c1 != c2
        # Different block_hash.
        c3 = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
            slot_anchor=SlotAnchor(slot=250_000_000, block_hash=b"\xaa" * 32),
        )
        assert c1 != c3

    def test_slot_anchor_must_be_slot_anchor_type(self):
        # AW-01-EXT: the type guard fires on a non-SlotAnchor value —
        # an accidental tuple/dict/bytes here would silently change the
        # commitment shape, so the function refuses up-front.
        with pytest.raises(TypeError, match="slot_anchor"):
            compute_input_commitment(
                WALLET, BASELINE_WIN, CURRENT_WIN,
                BASELINE_TXS, CURRENT_TXS, BASELINE_HASH,
                slot_anchor=(250_000_000, b"\x99" * 32),  # type: ignore[arg-type]
            )


# =============================================================================
# Empty transaction lists
# =============================================================================

class TestEmptyEdgeCases:
    """A new agent or one in a quiet epoch may have zero transactions —
    the commitment must still be defined and deterministic."""

    def test_empty_current_window_still_commits(self):
        c = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, current_transactions=(),
            baseline_hash=BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        assert len(c) == 32

    def test_empty_vs_non_empty_distinguished(self):
        c_empty = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, (), BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        c_one = compute_input_commitment(
            WALLET, BASELINE_WIN, CURRENT_WIN,
            BASELINE_TXS, (_tx("sigC1", 300),), BASELINE_HASH,
            slot_anchor=SLOT_ANCHOR,
        )
        assert c_empty != c_one


# =============================================================================
# Schema-version tag — folded in for future canonical-form changes
# =============================================================================

class TestSchemaVersion:

    def test_version_is_two(self):
        # AW-01-EXT bumped the canonical form from v1 to v2 to fold in the
        # Solana SlotAnchor. If this changes intentionally, also update
        # on-chain INPUT_COMMITMENT_VERSION so a stale-version commitment
        # cannot collide with a fresh-version one.
        assert INPUT_COMMITMENT_VERSION == 2


# =============================================================================
# Cross-node agreement quorum
# =============================================================================

class TestCommitmentsAgree:

    def test_unanimous_agreement(self):
        c = b"\xab" * 32
        majority, divergent = commitments_agree([c, c, c, c, c], quorum=3)
        assert majority == c
        assert divergent == frozenset()

    def test_minority_dissent_is_surfaced(self):
        c_good = b"\xab" * 32
        c_bad = b"\xcd" * 32
        # 4 honest, 1 poisoned -> majority commitment + the poisoned index
        # is in the divergent set.
        majority, divergent = commitments_agree(
            [c_good, c_good, c_good, c_good, c_bad], quorum=3,
        )
        assert majority == c_good
        assert divergent == frozenset({4})

    def test_no_quorum_returns_none(self):
        # 5 nodes, every node disagrees, quorum 3 — no majority exists.
        commitments = [bytes([i]) * 32 for i in range(5)]
        majority, divergent = commitments_agree(commitments, quorum=3)
        assert majority is None
        # Every index counted as divergent — there is no agreed baseline.
        assert divergent == frozenset({0, 1, 2, 3, 4})

    def test_wrong_commitment_length_rejected(self):
        with pytest.raises(ValueError, match="32 bytes"):
            commitments_agree([b"too-short"], quorum=1)

    def test_quorum_must_be_positive(self):
        with pytest.raises(ValueError, match="quorum"):
            commitments_agree([b"\xab" * 32], quorum=0)

    def test_3_of_5_split_minority(self):
        # Realistic 5-node cluster: 3 honest, 2 split (one poisoned, one
        # off in a unique third direction). The honest 3 form the
        # majority; both other indices land in `divergent`.
        good = b"\xaa" * 32
        bad_a = b"\xbb" * 32
        bad_b = b"\xcc" * 32
        majority, divergent = commitments_agree(
            [good, good, good, bad_a, bad_b], quorum=3,
        )
        assert majority == good
        assert divergent == frozenset({3, 4})
