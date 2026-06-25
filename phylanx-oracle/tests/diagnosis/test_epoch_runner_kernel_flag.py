"""
tests/diagnosis/test_epoch_runner_kernel_flag.py — epoch-runner integration
for the Day-36 diagnosis kernel feature flag.

The kernel is opt-in via `run_diagnosis_kernel=True` on `run_epoch(...)`.
With the flag OFF the runner observes ZERO change — `kernel_result` stays
None on every AgentEpochResult. With it ON, an agent whose
current-window transactions trip a detector carries a populated
`kernel_result` (a `KernelResult`) with a non-zero `failure_mode_bitmask`.

This file pins:
    * default off — every AgentEpochResult.kernel_result is None
    * flag on, no fire — kernel_result is a KernelResult, bitmask = 0
    * flag on, fires — bitmask = TOOL_LOOP bit
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from detection.consistency_context import ConsistencyContext
from detection.security_context import SecurityContext
from diagnosis.detectors import KernelResult
from diagnosis.taxonomy import FailureMode
from features.types import ExtractionWindow, Transaction
from oracle.epoch_runner import AgentEpochInput, run_epoch


NOW = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)
WINDOW = ExtractionWindow(start=NOW - timedelta(hours=2), end=NOW)
JUP = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"


def _baseline_txs() -> list[Transaction]:
    return [
        Transaction(
            signature=f"base{i:060d}",
            slot=500 + i,
            block_time=NOW - timedelta(days=2) + timedelta(seconds=i*100),
            success=True,
            program_ids=(JUP,),
            sol_change=-1000,
            fee=5000,
            counterparty="peerB",
        )
        for i in range(20)
    ]


def _loop_burst_txs() -> list[Transaction]:
    return [
        Transaction(
            signature=f"loop{i:060d}",
            slot=2000 + i,
            block_time=NOW - timedelta(seconds=60 - i*5),
            success=True,
            program_ids=(JUP,),
            sol_change=-1000,
            fee=5000,
            counterparty="peerA",
        )
        for i in range(8)
    ]


def _quiet_txs() -> list[Transaction]:
    return [
        Transaction(
            signature=f"quiet{i:059d}",
            slot=3000 + i,
            block_time=NOW - timedelta(minutes=30) + timedelta(minutes=i*5),
            success=True,
            program_ids=(JUP,),
            sol_change=-1000,
            fee=5000,
            counterparty="peerC",
        )
        for i in range(3)
    ]


def _agent_input(wallet: str, current_txs: list[Transaction]) -> AgentEpochInput:
    return AgentEpochInput(
        agent_wallet=wallet,
        baseline_transactions=_baseline_txs(),
        current_transactions=current_txs,
        baseline_window=ExtractionWindow(
            start=NOW - timedelta(days=3),
            end=NOW - timedelta(days=1),
        ),
        current_window=WINDOW,
        security_context=SecurityContext(),
        consistency_context=ConsistencyContext(),
    )


def _submit_stub(wallet: str, score_result) -> object:
    return {"wallet": wallet, "ok": True}


def test_flag_off_leaves_kernel_result_none():
    report = run_epoch(
        epoch_id=1,
        agent_inputs=[_agent_input("a1", _loop_burst_txs())],
        submit_fn=_submit_stub,
        computed_at=NOW,
    )
    assert len(report.results) == 1
    assert report.results[0].kernel_result is None


def test_flag_on_quiet_window_emits_clean_kernel_result():
    report = run_epoch(
        epoch_id=1,
        agent_inputs=[_agent_input("a1", _quiet_txs())],
        submit_fn=_submit_stub,
        computed_at=NOW,
        run_diagnosis_kernel=True,
    )
    r = report.results[0].kernel_result
    assert isinstance(r, KernelResult)
    assert r.failure_mode_bitmask == 0
    assert r.findings == ()


def test_flag_on_loop_burst_raises_tool_loop_bit():
    report = run_epoch(
        epoch_id=1,
        agent_inputs=[_agent_input("a1", _loop_burst_txs())],
        submit_fn=_submit_stub,
        computed_at=NOW,
        run_diagnosis_kernel=True,
    )
    r = report.results[0].kernel_result
    assert isinstance(r, KernelResult)
    expected_bit = 1 << (FailureMode.TOOL_LOOP.bit_length() - 1)
    assert r.failure_mode_bitmask & expected_bit
    assert any(f.detector_id == "tool_loop@1" for f in r.findings)
