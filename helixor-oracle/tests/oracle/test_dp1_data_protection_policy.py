"""
tests/oracle/test_dp1_data_protection_policy.py — DP-1 substrate pins.

The compliance gate (`audit/data_protection_check.py`) verifies the
substrate at boot. These tests pin the SHAPE of the substrate so a
refactor that quietly drops an enum member, breaks the erasability
biconditional, or skews a retention ceiling lights red AS A UNIT
TEST, not just as a CI audit failure.

Pins:
  - Every DataCategory has a declared policy.
  - The erasability biconditional holds (on-chain ⇒ non-erasable;
    off-chain ⇒ erasable, with the single REFUSAL_LOG carve-out).
  - On-chain policies have indefinite retention; off-chain policies
    have positive finite ceilings.
  - The pinned retention seconds match the audit-pinned day counts.
  - Lookup helpers (`get_policy`, `erasable_policies`,
    `non_erasable_policies`) round-trip the table correctly.
  - `RetentionPolicy.__post_init__` rejects all the forbidden
    combinations: on-chain + erasable, on-chain + finite ceiling,
    off-chain + non-erasable (except the carve-out), off-chain +
    indefinite, non-positive ceiling, empty description.
"""

from __future__ import annotations

import pytest

from oracle.data_protection_policy import (
    DataCategory,
    DataProtectionError,
    INDEFINITE,
    KAFKA_REFUSAL_RETENTION_SECONDS,
    KAFKA_TRANSACTIONS_RETENTION_SECONDS,
    LawfulBasis,
    PROMETHEUS_RETENTION_SECONDS,
    RETENTION_POLICIES,
    RetentionPolicy,
    StorageLocation,
    TIMESCALE_SCORE_RETENTION_SECONDS,
    TIMESCALE_TRANSACTION_RETENTION_SECONDS,
    erasable_policies,
    get_policy,
    is_on_chain,
    non_erasable_policies,
)


# ----------------------------------------------------------------------------
# Coverage — every DataCategory has at least one policy
# ----------------------------------------------------------------------------

def test_every_data_category_has_a_policy():
    """A new category added to the enum without a policy entry is a
    silent compliance regression — the audit gate would catch it,
    but this test catches it earlier."""
    covered = {p.category for p in RETENTION_POLICIES.values()}
    missing = set(DataCategory) - covered
    assert not missing, (
        f"DataCategory members without a RetentionPolicy: "
        f"{[m.value for m in missing]}"
    )


# ----------------------------------------------------------------------------
# Erasability biconditional — the load-bearing invariant
# ----------------------------------------------------------------------------

def test_on_chain_policies_are_never_erasable():
    for policy in RETENTION_POLICIES.values():
        if is_on_chain(policy.storage_location):
            assert policy.erasure_supported is False, (
                f"{policy.category.value} on "
                f"{policy.storage_location.value} declares "
                f"erasure_supported=True, but on-chain data is "
                f"structurally non-erasable"
            )


def test_on_chain_policies_have_indefinite_retention():
    for policy in RETENTION_POLICIES.values():
        if is_on_chain(policy.storage_location):
            assert policy.max_retention_seconds is INDEFINITE, (
                f"{policy.category.value} on "
                f"{policy.storage_location.value} declares a finite "
                f"retention ceiling, but on-chain data is structurally "
                f"indefinite"
            )


def test_off_chain_policies_are_erasable_except_refusal_log_carveout():
    """REFUSAL_LOG is the single explicit off-chain non-erasable
    carve-out — the OFAC-1 silent-delist transparency invariant
    requires the refusal records remain visible."""
    for policy in RETENTION_POLICIES.values():
        if is_on_chain(policy.storage_location):
            continue
        if policy.category is DataCategory.REFUSAL_LOG:
            assert policy.erasure_supported is False
            continue
        assert policy.erasure_supported is True, (
            f"{policy.category.value} on "
            f"{policy.storage_location.value} declares "
            f"erasure_supported=False outside the REFUSAL_LOG carve-out"
        )


def test_off_chain_policies_have_positive_finite_retention():
    for policy in RETENTION_POLICIES.values():
        if is_on_chain(policy.storage_location):
            continue
        assert policy.max_retention_seconds is not None, (
            f"{policy.category.value} on "
            f"{policy.storage_location.value} declares indefinite "
            f"retention but is off-chain"
        )
        assert policy.max_retention_seconds > 0


# ----------------------------------------------------------------------------
# Retention ceilings — pinned values match audit-pinned day counts
# ----------------------------------------------------------------------------

def test_timescale_transaction_retention_is_180_days():
    assert TIMESCALE_TRANSACTION_RETENTION_SECONDS == 180 * 24 * 3600


def test_timescale_score_retention_is_180_days():
    assert TIMESCALE_SCORE_RETENTION_SECONDS == 180 * 24 * 3600


def test_prometheus_retention_is_30_days():
    assert PROMETHEUS_RETENTION_SECONDS == 30 * 24 * 3600


def test_kafka_transactions_retention_is_7_days():
    assert KAFKA_TRANSACTIONS_RETENTION_SECONDS == 7 * 24 * 3600


def test_kafka_refusal_retention_is_30_days():
    """REFUSAL_LOG retention must be long enough for downstream audit
    pipes to ingest; 30 days mirrors the Prometheus floor."""
    assert KAFKA_REFUSAL_RETENTION_SECONDS == 30 * 24 * 3600


# ----------------------------------------------------------------------------
# Lookup helpers
# ----------------------------------------------------------------------------

def test_get_policy_returns_pinned_record():
    p = get_policy(
        DataCategory.TRANSACTION_HISTORY,
        StorageLocation.OFF_CHAIN_TIMESCALE,
    )
    assert p.max_retention_seconds == TIMESCALE_TRANSACTION_RETENTION_SECONDS
    assert p.erasure_supported is True
    assert p.lawful_basis is LawfulBasis.LEGITIMATE_INTEREST_FRAUD_PREVENTION


def test_get_policy_raises_on_unwired_pair():
    """A category that exists in the enum but has no policy for a
    given storage location should raise — the audit gate uses this
    to flag accidental drops."""
    with pytest.raises(DataProtectionError):
        get_policy(
            DataCategory.CERT_HISTORY,
            StorageLocation.OFF_CHAIN_TIMESCALE,  # cert history is on-chain
        )


def test_erasable_and_non_erasable_partition_is_complete():
    """The two helpers together must cover every policy."""
    erasable = set(erasable_policies())
    non_erasable = set(non_erasable_policies())
    all_policies = set(RETENTION_POLICIES.values())
    assert erasable | non_erasable == all_policies
    assert erasable.isdisjoint(non_erasable)


# ----------------------------------------------------------------------------
# RetentionPolicy.__post_init__ — forbidden combinations rejected
# ----------------------------------------------------------------------------

def test_on_chain_with_erasable_rejected():
    with pytest.raises(ValueError, match="erasure_supported=True"):
        RetentionPolicy(
            category=DataCategory.CERT_HISTORY,
            storage_location=StorageLocation.ON_CHAIN_SOLANA,
            max_retention_seconds=INDEFINITE,
            lawful_basis=LawfulBasis.LEGAL_OBLIGATION_AUDIT_TRAIL,
            erasure_supported=True,  # <- forbidden
            description="x",
        )


def test_on_chain_with_finite_retention_rejected():
    with pytest.raises(ValueError, match="indefinite"):
        RetentionPolicy(
            category=DataCategory.CERT_HISTORY,
            storage_location=StorageLocation.ON_CHAIN_SOLANA,
            max_retention_seconds=42,  # <- forbidden
            lawful_basis=LawfulBasis.LEGAL_OBLIGATION_AUDIT_TRAIL,
            erasure_supported=False,
            description="x",
        )


def test_off_chain_indefinite_retention_rejected():
    with pytest.raises(ValueError, match="finite ceiling"):
        RetentionPolicy(
            category=DataCategory.TRANSACTION_HISTORY,
            storage_location=StorageLocation.OFF_CHAIN_TIMESCALE,
            max_retention_seconds=INDEFINITE,  # <- forbidden off-chain
            lawful_basis=LawfulBasis.LEGITIMATE_INTEREST_FRAUD_PREVENTION,
            erasure_supported=True,
            description="x",
        )


def test_off_chain_non_erasable_outside_carveout_rejected():
    """Only REFUSAL_LOG is allowed to be off-chain + non-erasable."""
    with pytest.raises(ValueError, match="must be erasable"):
        RetentionPolicy(
            category=DataCategory.TRANSACTION_HISTORY,  # <- not the carve-out
            storage_location=StorageLocation.OFF_CHAIN_TIMESCALE,
            max_retention_seconds=180 * 24 * 3600,
            lawful_basis=LawfulBasis.LEGITIMATE_INTEREST_FRAUD_PREVENTION,
            erasure_supported=False,
            description="x",
        )


def test_zero_retention_seconds_rejected():
    with pytest.raises(ValueError, match="positive"):
        RetentionPolicy(
            category=DataCategory.TRANSACTION_HISTORY,
            storage_location=StorageLocation.OFF_CHAIN_TIMESCALE,
            max_retention_seconds=0,  # <- non-positive
            lawful_basis=LawfulBasis.LEGITIMATE_INTEREST_FRAUD_PREVENTION,
            erasure_supported=True,
            description="x",
        )


def test_empty_description_rejected():
    with pytest.raises(ValueError, match="description"):
        RetentionPolicy(
            category=DataCategory.TRANSACTION_HISTORY,
            storage_location=StorageLocation.OFF_CHAIN_TIMESCALE,
            max_retention_seconds=180 * 24 * 3600,
            lawful_basis=LawfulBasis.LEGITIMATE_INTEREST_FRAUD_PREVENTION,
            erasure_supported=True,
            description="   ",  # <- empty after strip
        )


# ----------------------------------------------------------------------------
# Pinned policies — each declared lawful basis is one we actually relied on
# ----------------------------------------------------------------------------

def test_refusal_log_basis_is_legal_obligation_sanctions():
    """The OFAC-1 carve-out is justified by the operator-side
    transparency duty, NOT by legitimate interest. A refactor that
    flips this to LEGITIMATE_INTEREST would weaken the carve-out
    rationale."""
    p = get_policy(
        DataCategory.REFUSAL_LOG,
        StorageLocation.OFF_CHAIN_KAFKA,
    )
    assert p.lawful_basis is LawfulBasis.LEGAL_OBLIGATION_SANCTIONS


def test_on_chain_cert_history_basis_is_audit_trail():
    p = get_policy(
        DataCategory.CERT_HISTORY,
        StorageLocation.ON_CHAIN_SOLANA,
    )
    assert p.lawful_basis is LawfulBasis.LEGAL_OBLIGATION_AUDIT_TRAIL
