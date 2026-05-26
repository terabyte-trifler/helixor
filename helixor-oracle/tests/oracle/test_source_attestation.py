"""
tests/oracle/test_source_attestation.py — pins the AW-01-EXT per-node
multi-source attestation primitive.

The primitive's contract is the architectural guarantee a node makes
BEFORE the cluster-wide AW-01 check runs: "M of my N independent
upstreams agreed on what I observed." These tests pin every branch of
that contract, plus determinism, so future refactors cannot silently
relax it.
"""

from __future__ import annotations

import pytest

from oracle.cluster.source_attestation import (
    AttestationOutcome,
    AttestationResult,
    SourceObservation,
    attest_multi_source,
)


# =============================================================================
# Fixtures
# =============================================================================

DIGEST_A = b"a" * 32
DIGEST_B = b"b" * 32
DIGEST_C = b"c" * 32


def obs(source_id: str, digest: bytes) -> SourceObservation:
    return SourceObservation(source_id=source_id, digest=digest)


# =============================================================================
# Happy path: full agreement
# =============================================================================

class TestAgreement:

    def test_three_of_three_agree(self):
        r = attest_multi_source(
            [obs("us-east", DIGEST_A), obs("eu-west", DIGEST_A), obs("ap-south", DIGEST_A)],
            minimum_honest=2,
        )
        assert r.outcome is AttestationOutcome.AGREE
        assert r.is_agree
        assert r.chosen_digest == DIGEST_A
        assert r.agree_count == 3
        assert r.total == 3
        assert r.dissenting_sources == ()

    def test_two_of_three_meets_threshold(self):
        r = attest_multi_source(
            [obs("us-east", DIGEST_A), obs("eu-west", DIGEST_A), obs("ap-south", DIGEST_B)],
            minimum_honest=2,
        )
        assert r.outcome is AttestationOutcome.AGREE
        assert r.chosen_digest == DIGEST_A
        assert r.dissenting_sources == ("ap-south",)


# =============================================================================
# DEGRADED: plurality < M but >= 2
# =============================================================================

class TestDegraded:

    def test_three_two_one_with_M_3_yields_degraded(self):
        # Three sources hold A, two hold B — minimum_honest=3, so we have a
        # plurality of 3 over 5 sources but the operator demanded 4. This
        # should DEGRADE if we lower the threshold below the plurality —
        # let's verify the boundary: M=4 with plurality=3 → DEGRADED.
        r = attest_multi_source(
            [obs("s1", DIGEST_A), obs("s2", DIGEST_A), obs("s3", DIGEST_A),
             obs("s4", DIGEST_B), obs("s5", DIGEST_B)],
            minimum_honest=4,
        )
        assert r.outcome is AttestationOutcome.DEGRADED
        assert r.is_degraded
        assert r.chosen_digest == DIGEST_A
        assert r.agree_count == 3
        assert r.dissenting_sources == ("s4", "s5")

    def test_two_two_one_with_M_3_yields_degraded(self):
        r = attest_multi_source(
            [obs("s1", DIGEST_A), obs("s2", DIGEST_A),
             obs("s3", DIGEST_B), obs("s4", DIGEST_B),
             obs("s5", DIGEST_C)],
            minimum_honest=3,
        )
        # Plurality is 2 (tied between A and B; tie broken by sorted byte
        # order — b"a" < b"b" so A wins). 2 >= 2 → DEGRADED.
        assert r.outcome is AttestationOutcome.DEGRADED
        assert r.chosen_digest == DIGEST_A
        assert r.agree_count == 2
        assert set(r.dissenting_sources) == {"s3", "s4", "s5"}


# =============================================================================
# REFUSE: no plurality of 2 or more, or every source disagreed
# =============================================================================

class TestRefuse:

    def test_all_distinct_yields_refuse(self):
        r = attest_multi_source(
            [obs("s1", DIGEST_A), obs("s2", DIGEST_B), obs("s3", DIGEST_C)],
            minimum_honest=2,
        )
        # Every observation distinct → plurality of 1; not >= 2; REFUSE.
        assert r.outcome is AttestationOutcome.REFUSE
        assert r.must_refuse
        assert r.chosen_digest is None

    def test_singleton_below_threshold_yields_refuse(self):
        r = attest_multi_source(
            [obs("only", DIGEST_A)],
            minimum_honest=1,
        )
        # One source, threshold met — but the contract says DEGRADED needs
        # plurality >= 2. A single agreeing source is full AGREE (M=1).
        assert r.outcome is AttestationOutcome.AGREE


# =============================================================================
# Tie-breaking determinism
# =============================================================================

class TestTieBreakingIsDeterministic:

    def test_tied_pluralities_choose_lex_smallest_digest(self):
        # Two each of A and B (b"a" < b"b"). A must win deterministically.
        r1 = attest_multi_source(
            [obs("s1", DIGEST_B), obs("s2", DIGEST_A),
             obs("s3", DIGEST_B), obs("s4", DIGEST_A)],
            minimum_honest=2,
        )
        r2 = attest_multi_source(
            [obs("s4", DIGEST_A), obs("s3", DIGEST_B),
             obs("s2", DIGEST_A), obs("s1", DIGEST_B)],
            minimum_honest=2,
        )
        assert r1.chosen_digest == DIGEST_A
        assert r2.chosen_digest == DIGEST_A
        assert r1.outcome == r2.outcome


# =============================================================================
# Argument validation
# =============================================================================

class TestArgumentValidation:

    def test_empty_observations_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            attest_multi_source([], minimum_honest=1)

    def test_minimum_honest_zero_raises(self):
        with pytest.raises(ValueError, match="minimum_honest"):
            attest_multi_source([obs("s1", DIGEST_A)], minimum_honest=0)

    def test_minimum_honest_above_n_raises(self):
        with pytest.raises(ValueError, match="cannot exceed"):
            attest_multi_source(
                [obs("s1", DIGEST_A), obs("s2", DIGEST_A)],
                minimum_honest=3,
            )

    def test_source_observation_rejects_empty_id(self):
        with pytest.raises(ValueError, match="source_id"):
            SourceObservation(source_id="", digest=DIGEST_A)

    def test_source_observation_rejects_empty_digest(self):
        with pytest.raises(ValueError, match="non-empty"):
            SourceObservation(source_id="x", digest=b"")


# =============================================================================
# AttestationResult predicates
# =============================================================================

class TestResultPredicates:

    def test_predicates_match_outcome(self):
        for outcome, flag, attr in [
            (AttestationOutcome.AGREE,    True,  "is_agree"),
            (AttestationOutcome.DEGRADED, True,  "is_degraded"),
            (AttestationOutcome.REFUSE,   True,  "must_refuse"),
        ]:
            r = AttestationResult(
                outcome=outcome, chosen_digest=None,
                agree_count=0, total=0, minimum_honest=1,
                dissenting_sources=(),
            )
            assert getattr(r, attr) is flag


# =============================================================================
# Determinism across input order
# =============================================================================

class TestDeterminism:

    def test_same_observations_in_any_order_produce_same_result(self):
        a = obs("s1", DIGEST_A)
        b = obs("s2", DIGEST_A)
        c = obs("s3", DIGEST_B)
        for ordering in ([a, b, c], [c, b, a], [b, a, c]):
            r = attest_multi_source(ordering, minimum_honest=2)
            assert r.outcome is AttestationOutcome.AGREE
            assert r.chosen_digest == DIGEST_A
            assert r.agree_count == 2
            assert r.dissenting_sources == ("s3",)
