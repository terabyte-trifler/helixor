"""
tests/slashing/test_slash_pipeline.py — the Day-22 done-when.

"A synthetic confirmed-compromise agent gets slashed automatically through
 the full pipeline; a merely-degrading agent does not."

These tests drive real synthetic agent profiles through the real
`run_epoch` — score -> submit -> slash-evaluate -> slash — with recording
stubs on the two on-chain seams, and assert the slash decision is correct
end to end.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from oracle.epoch_runner import run_epoch
from slashing import OffenseTier, SingleNodeConsensus, ThresholdConsensus
from slashing.consensus import NodeVerdict
from tests.oracle.agent_profiles import (
    profile_adversarial,
    profile_degrading,
    profile_stable_a,
)


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Recording seams — score submission + slash execution
# =============================================================================

def _recording_submit():
    calls: list[dict] = []

    def _submit(wallet: str, score_result) -> dict:
        record = {"wallet": wallet, "score": score_result.score}
        calls.append(record)
        return record

    return _submit, calls


def _recording_slash():
    """A slash_fn that records every execute_slash call — the on-chain seam."""
    calls: list[dict] = []

    def _slash(wallet: str, decision) -> dict:
        record = {
            "wallet": wallet,
            "tier": decision.tier,
            "reason": decision.reason,
        }
        calls.append(record)
        return record

    return _slash, calls


# =============================================================================
# THE DONE-WHEN — confirmed compromise is slashed, degradation is not
# =============================================================================

class TestDoneWhenSlashPipeline:

    def test_confirmed_compromise_agent_is_slashed(self):
        """A synthetic confirmed-compromise agent gets slashed automatically."""
        submit, _ = _recording_submit()
        slash, slash_calls = _recording_slash()

        report = run_epoch(
            epoch_id=22,
            agent_inputs=[profile_adversarial()],
            submit_fn=submit,
            slash_fn=slash,
            computed_at=REF_END,
        )

        result = report.results[0]
        # The adversarial agent's security dimension tripped IMMEDIATE_RED,
        # and (single-node) consensus confirmed it -> slashed.
        assert result.slash_decision is not None
        assert result.slash_decision.should_slash is True
        assert result.slash_decision.tier is OffenseTier.COMPROMISE
        assert result.slashed is True
        # The on-chain slash seam was actually called.
        assert len(slash_calls) == 1
        assert slash_calls[0]["tier"] is OffenseTier.COMPROMISE
        assert report.slashed_count == 1

    def test_merely_degrading_agent_is_not_slashed(self):
        """A merely-degrading agent does NOT get slashed."""
        submit, _ = _recording_submit()
        slash, slash_calls = _recording_slash()

        report = run_epoch(
            epoch_id=22,
            agent_inputs=[profile_degrading()],
            submit_fn=submit,
            slash_fn=slash,
            computed_at=REF_END,
        )

        result = report.results[0]
        # Degradation is not a slashable offense — no security compromise.
        assert result.slash_decision is not None
        assert result.slash_decision.should_slash is False
        assert result.slash_decision.tier is None
        assert result.slashed is False
        # The slash seam was NEVER called.
        assert len(slash_calls) == 0
        assert report.slashed_count == 0

    def test_stable_agent_is_not_slashed(self):
        submit, _ = _recording_submit()
        slash, slash_calls = _recording_slash()

        report = run_epoch(
            epoch_id=22, agent_inputs=[profile_stable_a()],
            submit_fn=submit, slash_fn=slash, computed_at=REF_END,
        )
        assert report.results[0].slashed is False
        assert len(slash_calls) == 0

    def test_mixed_epoch_slashes_only_the_compromised_agent(self):
        """In one epoch with both kinds of agent, exactly one is slashed."""
        submit, _ = _recording_submit()
        slash, slash_calls = _recording_slash()

        report = run_epoch(
            epoch_id=22,
            agent_inputs=[
                profile_stable_a(),
                profile_degrading(),
                profile_adversarial(),
            ],
            submit_fn=submit,
            slash_fn=slash,
            computed_at=REF_END,
        )

        # All three scored + submitted; exactly one slashed.
        assert report.agent_count == 3
        assert report.submitted_count == 3
        assert report.slashed_count == 1
        assert len(slash_calls) == 1
        # And it is the adversarial one.
        assert slash_calls[0]["wallet"].startswith("adversary")


# =============================================================================
# The slash step is wired correctly into the runner
# =============================================================================

class TestRunnerWiring:

    def test_slash_decision_recorded_even_without_slash_fn(self):
        # With no slash_fn the runner still EVALUATES (dry run) — the
        # decision is recorded but no execution happens.
        submit, _ = _recording_submit()
        report = run_epoch(
            epoch_id=22, agent_inputs=[profile_adversarial()],
            submit_fn=submit, slash_fn=None, computed_at=REF_END,
        )
        result = report.results[0]
        assert result.slash_decision is not None
        assert result.slash_decision.should_slash is True
        # ...but nothing was executed.
        assert result.slashed is False

    def test_slash_evaluation_runs_after_submission(self):
        # Submission still happens for a slashed agent — the slash step is
        # additive, it does not replace submission.
        submit, submit_calls = _recording_submit()
        slash, _ = _recording_slash()
        report = run_epoch(
            epoch_id=22, agent_inputs=[profile_adversarial()],
            submit_fn=submit, slash_fn=slash, computed_at=REF_END,
        )
        assert len(submit_calls) == 1
        assert report.results[0].submitted is True
        assert report.results[0].slashed is True

    def test_slash_execution_failure_is_contained(self):
        # A slash_fn that raises does not crash the epoch — it becomes an
        # error on that agent's result.
        submit, _ = _recording_submit()

        def _failing_slash(wallet, decision):
            raise RuntimeError("validator unreachable")

        report = run_epoch(
            epoch_id=22, agent_inputs=[profile_adversarial()],
            submit_fn=submit, slash_fn=_failing_slash, computed_at=REF_END,
        )
        result = report.results[0]
        assert result.slashed is False
        assert "slash execution failed" in result.error
        # The decision itself was still computed.
        assert result.slash_decision.should_slash is True


# =============================================================================
# Consensus integration — a cluster policy changes the outcome
# =============================================================================

class TestConsensusIntegration:

    def test_threshold_consensus_blocks_slash_without_quorum(self):
        # With a 2-of-3 ThresholdConsensus but only ONE node voting (the
        # runner produces one verdict), quorum is not met -> no slash, even
        # for the adversarial agent. This proves consensus genuinely gates.
        submit, _ = _recording_submit()
        slash, slash_calls = _recording_slash()

        report = run_epoch(
            epoch_id=22,
            agent_inputs=[profile_adversarial()],
            submit_fn=submit,
            slash_fn=slash,
            consensus=ThresholdConsensus(cluster_size=3, threshold=2),
            computed_at=REF_END,
        )
        result = report.results[0]
        # Security flagged, but 1/3 < 2/3 threshold -> not confirmed.
        assert result.slash_decision.security_immediate_red is True
        assert result.slash_decision.consensus_confirmed is False
        assert result.slash_decision.should_slash is False
        assert len(slash_calls) == 0

    def test_single_node_consensus_is_the_default(self):
        # No consensus arg -> SingleNodeConsensus -> the adversarial agent
        # IS slashed (one node, its verdict stands).
        submit, _ = _recording_submit()
        slash, slash_calls = _recording_slash()
        report = run_epoch(
            epoch_id=22, agent_inputs=[profile_adversarial()],
            submit_fn=submit, slash_fn=slash, computed_at=REF_END,
        )
        assert report.results[0].slashed is True
        assert len(slash_calls) == 1


# =============================================================================
# Determinism — the full pipeline
# =============================================================================

class TestDeterminism:

    def test_slash_pipeline_is_deterministic(self):
        def _run():
            submit, _ = _recording_submit()
            slash, slash_calls = _recording_slash()
            report = run_epoch(
                epoch_id=22,
                agent_inputs=[
                    profile_stable_a(), profile_degrading(),
                    profile_adversarial(),
                ],
                submit_fn=submit, slash_fn=slash, computed_at=REF_END,
            )
            return (
                report.slashed_count,
                tuple(r.slashed for r in report.results),
                tuple(
                    r.slash_decision.tier for r in report.results
                ),
            )

        first = _run()
        for _ in range(6):
            assert _run() == first
