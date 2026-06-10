"""
tests/diagnosis/test_detectors_day36.py — per-detector behaviour + boundary pin tests.

Each Day-36 detector gets:
    * a clean (no-fire) case
    * a positive case at the boundary (+1 above threshold)
    * a negative case at the boundary (-1 below threshold)
    * shape pins on the emitted DiagnosisFinding

The kernel manifest hash is pinned in its own test_kernel_determinism.py.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from diagnosis.detectors import (
    arg_validation,
    cost_blowup,
    counterparty_concentration,
    excessive_agency,
    rapid_drain,
    timing_anomaly,
    tool_loop,
    unauthorized_program,
)
from diagnosis.remediation import RemediationCode
from diagnosis.taxonomy import FailureMode
from features.types import ExtractionWindow, Transaction


NOW = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)
WINDOW = ExtractionWindow(start=NOW - timedelta(hours=2), end=NOW)
JUP = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
RAY = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"
SYSTEM = "11111111111111111111111111111111"


def _tx(
    i: int,
    *,
    block_time=None,
    success=True,
    program_ids=(JUP,),
    sol_change=-1000,
    fee=5000,
    priority_fee=0,
    counterparty: str | None = None,
) -> Transaction:
    return Transaction(
        signature=f"sig{i:061d}",
        slot=1000 + i,
        block_time=block_time or (NOW - timedelta(minutes=30) + timedelta(seconds=i)),
        success=success,
        program_ids=program_ids,
        sol_change=sol_change,
        fee=fee,
        priority_fee=priority_fee,
        counterparty=counterparty,
    )


# ─────────────────────────────────────────────────────────────────────────────
# tool_loop
# ─────────────────────────────────────────────────────────────────────────────

class TestToolLoop:
    def test_no_fire_below_threshold(self):
        txs = [
            _tx(i, block_time=NOW - timedelta(seconds=60 - i*5))
            for i in range(tool_loop.LOOP_THRESHOLD - 1)
        ]
        assert tool_loop.detect(txs, WINDOW) is None

    def test_fires_at_threshold(self):
        txs = [
            _tx(i, block_time=NOW - timedelta(seconds=60 - i*5))
            for i in range(tool_loop.LOOP_THRESHOLD)
        ]
        f = tool_loop.detect(txs, WINDOW)
        assert f is not None
        assert f.label_bit == FailureMode.TOOL_LOOP.bit_length() - 1
        assert len(f.evidence_spans) == tool_loop.LOOP_THRESHOLD
        assert f.remediation_codes & RemediationCode.PAUSE_AGENT
        assert 0.5 <= f.confidence <= 1.0

    def test_no_fire_when_spread_past_burst(self):
        txs = [
            _tx(i, block_time=NOW - timedelta(seconds=600 - i*tool_loop.LOOP_BURST_SECONDS))
            for i in range(tool_loop.LOOP_THRESHOLD + 2)
        ]
        assert tool_loop.detect(txs, WINDOW) is None

    def test_no_fire_when_alternating_programs(self):
        progs = (JUP, RAY)
        txs = [
            _tx(i, block_time=NOW - timedelta(seconds=30 - i),
                program_ids=(progs[i % 2],))
            for i in range(tool_loop.LOOP_THRESHOLD + 4)
        ]
        assert tool_loop.detect(txs, WINDOW) is None


# ─────────────────────────────────────────────────────────────────────────────
# cost_blowup
# ─────────────────────────────────────────────────────────────────────────────

class TestCostBlowup:
    def test_no_fire_below_threshold(self):
        below = cost_blowup.COST_BLOWUP_LAMPORTS - 1
        txs = [_tx(0, fee=below, priority_fee=0)]
        assert cost_blowup.detect(txs, WINDOW) is None

    def test_fires_at_threshold(self):
        txs = [_tx(0, fee=cost_blowup.COST_BLOWUP_LAMPORTS, priority_fee=0)]
        f = cost_blowup.detect(txs, WINDOW)
        assert f is not None
        assert f.label_bit == FailureMode.COST_BLOWUP.bit_length() - 1
        assert f.remediation_codes & RemediationCode.DECREASE_RATE_LIMITS

    def test_evidence_capped(self):
        per = cost_blowup.COST_BLOWUP_LAMPORTS  # huge fee, many txs
        txs = [_tx(i, fee=per) for i in range(cost_blowup.TOP_EVIDENCE_COUNT + 5)]
        f = cost_blowup.detect(txs, WINDOW)
        assert f is not None
        assert len(f.evidence_spans) == cost_blowup.TOP_EVIDENCE_COUNT


# ─────────────────────────────────────────────────────────────────────────────
# excessive_agency
# ─────────────────────────────────────────────────────────────────────────────

class TestExcessiveAgency:
    def test_abstains_unknown_domain(self):
        txs = [_tx(i) for i in range(10)]
        assert excessive_agency.detect(txs, WINDOW, declared_domain="quantum-cats") is None

    def test_no_fire_when_domain_matches(self):
        txs = [_tx(i, program_ids=(JUP,)) for i in range(10)]
        # defi-trading expects swap-dominated; JUP -> SWAP
        assert excessive_agency.detect(txs, WINDOW, declared_domain="defi-trading") is None

    def test_fires_when_domain_diverges(self):
        # lending agent that only swaps -> TVD ~= 1.2 vs lending profile
        txs = [_tx(i, program_ids=(JUP,)) for i in range(10)]
        f = excessive_agency.detect(txs, WINDOW, declared_domain="lending")
        assert f is not None
        assert f.label_bit == FailureMode.EXCESSIVE_AGENCY.bit_length() - 1
        assert f.remediation_codes & RemediationCode.REDUCE_AUTONOMY


# ─────────────────────────────────────────────────────────────────────────────
# unauthorized_program
# ─────────────────────────────────────────────────────────────────────────────

class TestUnauthorizedProgram:
    def test_abstains_without_allowlist(self):
        txs = [_tx(i, program_ids=(JUP,)) for i in range(5)]
        assert unauthorized_program.detect(
            txs, WINDOW, allowed_programs=frozenset(),
        ) is None

    def test_no_fire_inside_allowlist(self):
        txs = [_tx(i, program_ids=(JUP,)) for i in range(5)]
        assert unauthorized_program.detect(
            txs, WINDOW, allowed_programs=frozenset({JUP}),
        ) is None

    def test_fires_on_first_violation(self):
        txs = [_tx(0, program_ids=(RAY,))]
        f = unauthorized_program.detect(
            txs, WINDOW, allowed_programs=frozenset({JUP}),
        )
        assert f is not None
        assert f.label_bit == FailureMode.TOOL_MISUSE.bit_length() - 1
        assert len(f.evidence_spans) == 1


# ─────────────────────────────────────────────────────────────────────────────
# rapid_drain
# ─────────────────────────────────────────────────────────────────────────────

class TestRapidDrain:
    def test_no_fire_on_small_outflow(self):
        txs = [_tx(0, sol_change=-(rapid_drain.DRAIN_THRESHOLD_LAMPORTS // 4))]
        assert rapid_drain.detect(txs, WINDOW) is None

    def test_fires_at_threshold(self):
        txs = [
            _tx(0, block_time=NOW - timedelta(seconds=10),
                sol_change=-rapid_drain.DRAIN_THRESHOLD_LAMPORTS),
        ]
        f = rapid_drain.detect(txs, WINDOW)
        assert f is not None
        assert f.label_bit == FailureMode.DATA_LEAKAGE.bit_length() - 1
        assert f.remediation_codes & RemediationCode.PAUSE_AGENT

    def test_ignores_inflows(self):
        txs = [_tx(0, sol_change=+rapid_drain.DRAIN_THRESHOLD_LAMPORTS * 10)]
        assert rapid_drain.detect(txs, WINDOW) is None

    def test_window_slide(self):
        # Two outflows spaced just outside the slide window: only the larger
        # contributes; if it is below threshold, no fire.
        half = rapid_drain.DRAIN_THRESHOLD_LAMPORTS // 2 - 1
        txs = [
            _tx(0, block_time=NOW - timedelta(seconds=1000), sol_change=-half),
            _tx(1, block_time=NOW - timedelta(seconds=10),   sol_change=-half),
        ]
        assert rapid_drain.detect(txs, WINDOW) is None


# ─────────────────────────────────────────────────────────────────────────────
# counterparty_concentration
# ─────────────────────────────────────────────────────────────────────────────

class TestCounterpartyConcentration:
    def test_no_fire_below_min_typed(self):
        txs = [_tx(i, counterparty="peerA") for i in range(counterparty_concentration.MIN_TYPED_TXS - 1)]
        assert counterparty_concentration.detect(txs, WINDOW) is None

    def test_fires_on_dominant_peer(self):
        txs = [_tx(i, counterparty="peerA") for i in range(counterparty_concentration.MIN_TYPED_TXS)]
        f = counterparty_concentration.detect(txs, WINDOW)
        assert f is not None
        assert f.label_bit == FailureMode.IDENTITY_PRIVILEGE_ABUSE.bit_length() - 1
        assert f.remediation_codes & RemediationCode.BLOCK_AGENT_PEER

    def test_no_fire_when_spread(self):
        # Half-half between two peers -> share 0.5 < MAX_SHARE
        txs: list[Transaction] = []
        for i in range(counterparty_concentration.MIN_TYPED_TXS * 2):
            txs.append(_tx(i, counterparty=f"peer{i % 2}"))
        assert counterparty_concentration.detect(txs, WINDOW) is None


# ─────────────────────────────────────────────────────────────────────────────
# timing_anomaly
# ─────────────────────────────────────────────────────────────────────────────

class TestTimingAnomaly:
    def test_no_fire_with_sparse_window(self):
        txs = [_tx(i, block_time=NOW - timedelta(seconds=600 - i*60)) for i in range(timing_anomaly.MIN_SAMPLE + 1)]
        assert timing_anomaly.detect(txs, WINDOW) is None

    def test_fires_on_bot_burst(self):
        txs = [_tx(i, block_time=NOW - timedelta(milliseconds=2000 - i*100))
               for i in range(timing_anomaly.MIN_SAMPLE + 1)]
        f = timing_anomaly.detect(txs, WINDOW)
        assert f is not None
        assert f.label_bit == FailureMode.LATENCY_DEGRADATION.bit_length() - 1


# ─────────────────────────────────────────────────────────────────────────────
# arg_validation
# ─────────────────────────────────────────────────────────────────────────────

class TestArgValidation:
    def test_no_fire_clean_run(self):
        txs = [_tx(i, success=True) for i in range(10)]
        assert arg_validation.detect(txs, WINDOW) is None

    def test_fires_above_threshold(self):
        # 4 failed / 10 = 0.40 > 0.30 threshold
        txs = [_tx(i, success=(i >= 4)) for i in range(10)]
        f = arg_validation.detect(txs, WINDOW)
        assert f is not None
        assert f.label_bit == FailureMode.TOOL_MISUSE.bit_length() - 1
        assert len(f.evidence_spans) == 4

    def test_no_fire_below_min_failed(self):
        # 2 failed / 4 = 0.50 rate but failed count < MIN_FAILED -> skip
        txs = [_tx(i, success=(i >= 2)) for i in range(4)]
        assert arg_validation.detect(txs, WINDOW) is None
