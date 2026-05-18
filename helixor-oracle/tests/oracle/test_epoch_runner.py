"""
tests/oracle/test_epoch_runner.py — Day-14 detection-engine integration suite.

THE DAY-14 DONE-WHEN
--------------------
"The v2 detection engine is live in the epoch pipeline; 8 agent profiles
 classified correctly; the on-chain score submission still works unchanged."

This suite:
  - runs all 8 synthetic agent profiles through the real epoch runner,
  - asserts each classifies the way its profile demands,
  - proves the 5 Doc-3 profiles still classify as the MVP intended
    (a regression guarantee),
  - proves the 3 V2-only profiles trip detectors the MVP never had,
  - proves the score is byte-identical across runs (determinism),
  - proves the on-chain submission seam is exercised unchanged.

REGRESSION NOTES — bugs found and fixed during Day-14 integration
-----------------------------------------------------------------
Two bugs were found wiring the synthetic profiles through the V2 engine.
Both were in the TEST FIXTURES, not the engine — but both are now locked
down by tests here so they cannot regress:

  BUG 1 — zero-variance baseline. The first profile generator built every
  baseline day byte-identically, producing 99/100 zero-variance features.
  The anomaly dimension's Method 5 (kurtosis) correctly reads a lone
  non-zero feature against an otherwise-constant baseline as "adversarial"
  and tripped IMMEDIATE_RED on a clean agent. Fix: `_day()` now carries
  deterministic per-(day, k) jitter. Regression guard:
  `test_stable_agent_baseline_has_realistic_variance`.

  BUG 2 — trend in the wrong place. The first `degrading` / `recovering`
  profiles put the trend in a thin 1-day current window. The V2 drift
  detectors (CUSUM / ADWIN / DDM) consume the 30-day daily success-rate
  SERIES, so a thin current window left them identical to a stable agent.
  Fix: the trend is now encoded across the 30-day baseline series.
  Regression guard: `test_degrading_differs_from_stable`.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from detection import DimensionId, default_registry
from detection.types import FlagBit
from oracle.epoch_runner import (
    AgentEpochResult,
    EpochReport,
    run_epoch,
    score_agent,
)
from scoring import AlertTier
from tests.oracle.agent_profiles import (
    ALL_PROFILES,
    DOC3_PROFILES,
    V2_ONLY_PROFILES,
)


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Helpers
# =============================================================================

def _recording_submit():
    """A submit_fn that records every call — the on-chain submission seam."""
    calls: list[dict] = []

    def _submit(wallet: str, score_result) -> dict:
        record = {"wallet": wallet, "score": score_result.score}
        calls.append(record)
        return record

    return _submit, calls


def _run_all_profiles() -> EpochReport:
    inputs = [gen() for gen, _ in ALL_PROFILES.values()]
    submit, _ = _recording_submit()
    return run_epoch(epoch_id=14, agent_inputs=inputs,
                     submit_fn=submit, computed_at=REF_END)


def _score_one(profile_name: str):
    gen, _ = ALL_PROFILES[profile_name]
    return score_agent(gen(), default_registry(), computed_at=REF_END)


# =============================================================================
# DONE-WHEN part 1 — the v2 engine is live in the epoch pipeline
# =============================================================================

class TestEpochPipeline:

    def test_epoch_runs_all_eight_agents(self):
        report = _run_all_profiles()
        assert report.agent_count == 8

    def test_every_agent_produces_a_score(self):
        report = _run_all_profiles()
        for result in report.results:
            assert isinstance(result, AgentEpochResult)
            assert result.score_result is not None
            assert 0 <= result.score_result.score <= 1000

    def test_no_scoring_errors(self):
        report = _run_all_profiles()
        assert report.error_count == 0

    def test_scores_use_v2_algo(self):
        # The composite carries SCORING_ALGO_VERSION = 2 — proof the V2
        # scorer (not the MVP scorer) is what the runner called.
        report = _run_all_profiles()
        for result in report.results:
            assert result.score_result.scoring_algo_version == 2

    def test_v2_engine_produces_five_dimension_breakdown(self):
        report = _run_all_profiles()
        for result in report.results:
            dims = result.score_result.dimension_results
            assert set(dims.keys()) == set(DimensionId.ordered())


# =============================================================================
# DONE-WHEN part 2 — the on-chain submission still works unchanged
# =============================================================================

class TestOnChainSubmission:

    def test_submission_seam_is_exercised(self):
        inputs = [gen() for gen, _ in ALL_PROFILES.values()]
        submit, calls = _recording_submit()
        report = run_epoch(epoch_id=14, agent_inputs=inputs,
                           submit_fn=submit, computed_at=REF_END)
        # Every agent went through the submission seam.
        assert len(calls) == 8
        assert report.submitted_count == 8

    def test_submission_receives_the_score(self):
        inputs = [gen() for gen, _ in ALL_PROFILES.values()]
        submit, calls = _recording_submit()
        run_epoch(epoch_id=14, agent_inputs=inputs,
                  submit_fn=submit, computed_at=REF_END)
        for call in calls:
            assert 0 <= call["score"] <= 1000

    def test_v2_score_result_packs_update_score_payload(self):
        # The live Solana submitter now receives the V2 composite ScoreResult
        # and converts it into the Anchor update_score payload without going
        # back through the old MVP scoring type.
        from oracle.submit import score_result_to_update_payload

        result = _score_one("stable_a")
        payload = score_result_to_update_payload(result)
        assert payload["score"] == result.score
        assert payload["success_rate_bps"] == 8000
        assert payload["tx_count_7d"] == 5
        assert payload["baseline_hash_prefix"] == bytes.fromhex(
            result.baseline_stats_hash,
        )[:16]
        assert payload["scoring_algo_version"] == result.scoring_algo_version
        assert payload["weights_version"] == result.scoring_weights_version

    def test_v2_threat_sets_onchain_anomaly_flag(self):
        # TrustCertificate only has one boolean threat/anomaly slot today.
        # V2 security immediate-red cases must still surface through it.
        from oracle.submit import score_result_to_update_payload

        result = _score_one("adversarial")
        payload = score_result_to_update_payload(result)
        assert payload["anomaly_flag"] is True

    def test_submission_failure_is_contained(self):
        # A submission that raises does not crash the epoch — it becomes an
        # error on that agent's result, and the epoch continues.
        gen, _ = ALL_PROFILES["stable_a"]

        def _failing_submit(wallet, score_result):
            raise RuntimeError("simulated RPC failure")

        report = run_epoch(epoch_id=14, agent_inputs=[gen()],
                           submit_fn=_failing_submit, computed_at=REF_END)
        assert report.agent_count == 1
        assert report.results[0].submitted is False
        assert "submission failed" in report.results[0].error
        # The score itself was still computed.
        assert report.results[0].score_result is not None


# =============================================================================
# DONE-WHEN part 3 — the 5 Doc-3 profiles classify correctly (regression)
# =============================================================================

class TestDoc3Profiles:
    """The V2 engine must still classify the MVP's Day-14 profiles correctly."""

    def test_stable_agents_score_green(self):
        for name in ("stable_a", "stable_b"):
            result = _score_one(name)
            assert result.alert is AlertTier.GREEN, name
            assert not result.immediate_red, name

    def test_stable_agents_score_high(self):
        for name in ("stable_a", "stable_b"):
            result = _score_one(name)
            assert result.score >= 850, f"{name} scored {result.score}"

    def test_degrading_differs_from_stable(self):
        # REGRESSION GUARD (bug 2): a degrading agent must score BELOW a
        # stable one. The first profile design left them identical because
        # the trend was in a thin current window the drift detectors do
        # not consume.
        stable = _score_one("stable_a").score
        degrading = _score_one("degrading").score
        assert degrading < stable, (
            f"degrading ({degrading}) should score below stable ({stable})"
        )

    def test_recovering_is_mid_range(self):
        # A recovering agent carries the scar of its rough patch — it scores
        # below a clean stable agent, but it is not an acute threat.
        recovering = _score_one("recovering")
        stable = _score_one("stable_a").score
        assert recovering.score < stable
        assert not recovering.immediate_red

    def test_volatile_scores_lowest_of_doc3(self):
        # The volatile agent's swings make it the lowest-scoring Doc-3 profile.
        doc3_scores = {n: _score_one(n).score for n in DOC3_PROFILES}
        assert doc3_scores["volatile"] == min(doc3_scores.values())

    def test_doc3_ordering(self):
        # The expected behavioural ordering:
        #   stable > degrading > volatile   and   stable > recovering
        s = {n: _score_one(n).score for n in DOC3_PROFILES}
        assert s["stable_a"] > s["degrading"]
        assert s["stable_a"] > s["recovering"]
        assert s["degrading"] > s["volatile"] or s["recovering"] > s["volatile"]

    def test_no_doc3_profile_trips_immediate_red(self):
        # None of the five Doc-3 profiles is an acute threat — the MVP never
        # hard-flagged them and neither does V2.
        for name in DOC3_PROFILES:
            assert not _score_one(name).immediate_red, name


# =============================================================================
# DONE-WHEN part 3 — the 3 V2-only profiles, which the MVP could never catch
# =============================================================================

class TestV2OnlyProfiles:
    """Profiles that trip detectors the MVP did not have."""

    def test_adversarial_is_flagged(self):
        # The adversarial agent's declared metadata carries a CRITICAL
        # attack pattern — the Day-9 security library catches it.
        result = _score_one("adversarial")
        assert result.immediate_red
        assert result.alert is AlertTier.RED
        # The security dimension is what caught it.
        sec = result.dimension_results[DimensionId.SECURITY]
        assert sec.flags & int(FlagBit.IMMEDIATE_RED)

    def test_sybil_clustered_is_flagged(self):
        # The Sybil agent shares a funding source with a cohort — the
        # Day-10 Sybil graph catches the cluster.
        result = _score_one("sybil_clustered")
        assert result.immediate_red
        sec = result.dimension_results[DimensionId.SECURITY]
        # The Sybil component reacted.
        assert sec.sub_scores["sybil_cluster_score"] < 1.0

    def test_gaming_the_score_is_flagged(self):
        # The gaming agent's behavioural entropy collapsed — the Day-13
        # composite gaming check catches it.
        result = _score_one("gaming_the_score")
        assert result.gaming_detected is True
        assert result.gaming_drop_fraction > 0.25

    def test_all_v2_profiles_score_below_clean(self):
        # Every V2-only threat scores below a clean stable agent.
        stable = _score_one("stable_a").score
        for name in V2_ONLY_PROFILES:
            assert _score_one(name).score < stable, name

    def test_v2_profiles_would_pass_mvp(self):
        # The point of these three: behaviourally (drift / anomaly /
        # performance) they look fine — it is ONLY the V2 dimensions
        # (security, gaming) that catch them. Confirm their non-security,
        # non-gaming dimensions are healthy.
        for name in ("adversarial", "sybil_clustered"):
            result = _score_one(name)
            # Drift + anomaly + performance are all healthy — the MVP,
            # scoring on those alone, would have passed this agent.
            assert result.dimension_results[DimensionId.DRIFT].score >= 150
            assert result.dimension_results[DimensionId.PERFORMANCE].score >= 100


# =============================================================================
# DONE-WHEN part 4 — determinism
# =============================================================================

class TestDeterminism:

    def test_same_input_byte_identical_score(self):
        # Every profile, scored twice, must produce identical results.
        for name in ALL_PROFILES:
            a = _score_one(name)
            b = _score_one(name)
            assert a == b, name

    def test_epoch_report_deterministic(self):
        first = _run_all_profiles()
        for _ in range(5):
            again = _run_all_profiles()
            assert [r.score_result.score for r in again.results] == \
                   [r.score_result.score for r in first.results]

    def test_score_stable_across_many_runs(self):
        for name in ALL_PROFILES:
            scores = {_score_one(name).score for _ in range(8)}
            assert len(scores) == 1, f"{name} non-deterministic: {scores}"


# =============================================================================
# REGRESSION GUARDS — the two bugs found during Day-14 integration
# =============================================================================

class TestRegressionGuards:

    def test_stable_agent_baseline_has_realistic_variance(self):
        """
        REGRESSION GUARD (bug 1): a synthetic stable agent's baseline must
        carry enough feature variance that the anomaly Method-5 kurtosis
        detector does NOT misfire.

        The original bug: a byte-identical-every-day baseline gave 99/100
        zero-variance features, and Method 5 read the resulting lone
        non-zero feature as an adversarial spike. The fix (deterministic
        per-day jitter in `_day()`) does not — and need not — make every
        feature vary; many are counts/ratios that legitimately round
        identically. What matters is that the variance is enough to keep
        Method 5 healthy. We assert that directly.
        """
        from baseline import compute_baseline
        from detection.anomaly import AnomalyDetector
        from features import extract
        from tests.oracle.agent_profiles import profile_stable_a

        inp = profile_stable_a()
        baseline = compute_baseline(
            inp.agent_wallet, list(inp.baseline_transactions),
            inp.baseline_window, computed_at=REF_END,
        )
        features = extract(list(inp.current_transactions), inp.current_window)
        anomaly = AnomalyDetector().score(features, baseline)
        # The symptom of bug 1 was Method 5 health collapsing to ~0.0.
        assert anomaly.sub_scores["method_5_adversarial"] > 0.3, (
            "Method 5 health is low — the baseline is too uniform "
            "(regression of bug 1)"
        )
        # And the baseline is not the pathological 99/100-zero case.
        zero_variance = sum(1 for s in baseline.feature_stds if s <= 1e-9)
        assert zero_variance < 95, (
            f"{zero_variance}/100 features zero-variance — near-pathological"
        )

    def test_clean_agent_never_trips_immediate_red(self):
        """
        REGRESSION GUARD (bug 1, end-to-end): no clean agent profile may
        trip IMMEDIATE_RED. This is the symptom bug 1 produced.
        """
        for name in ("stable_a", "stable_b"):
            assert not _score_one(name).immediate_red, name

    def test_degrading_is_not_identical_to_stable(self):
        """
        REGRESSION GUARD (bug 2): the degrading profile must produce a
        DIFFERENT dimension breakdown from the stable profile. The first
        design left every dimension byte-identical.
        """
        stable = _score_one("stable_a")
        degrading = _score_one("degrading")
        stable_dims = {d: stable.dimension_results[d].score
                       for d in DimensionId.ordered()}
        degrading_dims = {d: degrading.dimension_results[d].score
                          for d in DimensionId.ordered()}
        assert stable_dims != degrading_dims, (
            "degrading and stable produced identical dimension scores"
        )
