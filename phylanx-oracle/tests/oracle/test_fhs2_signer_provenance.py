"""
tests/oracle/test_fhs2_signer_provenance.py — FHS-2 per-signer
provenance attestation gate.

Pins:
  - Constants (MAX_SIGNERS_PER_HOST=1, MAX_SIGNERS_PER_REGION=2,
    MIN_DISTINCT_HOSTS=3).
  - Healthy 3-of-5 set on 3 distinct hosts + 2 regions is OK.
  - Two signers sharing host_id refused.
  - Three signers sharing region refused.
  - Missing host_id refused with MISSING_ATTESTATION.
  - Missing cloud_region refused with MISSING_ATTESTATION.
  - Below-threshold distinct hosts refused.
  - Multiple violations report all reason codes.
  - Enforcement raises SignerProvenanceError with the report
    attached on refusal.
  - Audit-scenario: attacker compromises ONE physical machine
    running two cluster HSMs; the verifier refuses the threshold
    set with SIGNERS_SHARE_HOST.
"""

from __future__ import annotations

import pytest

from oracle.signer_provenance import (
    MAX_SIGNERS_PER_HOST,
    MAX_SIGNERS_PER_REGION,
    MIN_DISTINCT_HOSTS,
    PROVENANCE_OK,
    PROVENANCE_REFUSED,
    REASON_INSUFFICIENT_DISTINCT_HOSTS,
    REASON_MISSING_ATTESTATION,
    REASON_SIGNERS_OVER_REGION_CAP,
    REASON_SIGNERS_SHARE_HOST,
    SignerAttestation,
    SignerProvenanceError,
    enforce_signer_provenance,
    verify_signer_provenance,
)


def _att(pubkey: str, host: str | None, region: str | None) -> SignerAttestation:
    return SignerAttestation(
        signer_pubkey=pubkey, host_id=host, cloud_region=region,
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert MAX_SIGNERS_PER_HOST == 1
    assert MAX_SIGNERS_PER_REGION == 2
    assert MIN_DISTINCT_HOSTS == 3


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_healthy_3_of_5_set_is_ok():
    # 3 signatures from 3 distinct hosts across 2 regions.
    report = verify_signer_provenance([
        _att("kA", "h-aws-1", "aws:us-east-1"),
        _att("kB", "h-gcp-1", "gcp:europe-west-4"),
        _att("kC", "h-aws-2", "aws:us-east-1"),
    ])
    assert report.is_allowed
    assert report.status == PROVENANCE_OK
    assert report.distinct_hosts == 3
    assert report.reasons == ()


# ---------------------------------------------------------------------------
# Host-collision refusal
# ---------------------------------------------------------------------------

def test_two_signers_sharing_host_refused():
    report = verify_signer_provenance([
        _att("kA", "h-aws-1", "aws:us-east-1"),
        _att("kB", "h-aws-1", "aws:us-east-1"),  # SAME host
        _att("kC", "h-gcp-1", "gcp:europe-west-4"),
    ])
    assert not report.is_allowed
    assert report.status == PROVENANCE_REFUSED
    assert REASON_SIGNERS_SHARE_HOST in report.reasons
    assert "h-aws-1" in report.over_host_cap_hosts


# ---------------------------------------------------------------------------
# Region-cap refusal
# ---------------------------------------------------------------------------

def test_three_signers_sharing_region_refused():
    report = verify_signer_provenance([
        _att("kA", "h-aws-1", "aws:us-east-1"),
        _att("kB", "h-aws-2", "aws:us-east-1"),
        _att("kC", "h-aws-3", "aws:us-east-1"),  # 3rd in same region
    ])
    assert not report.is_allowed
    assert REASON_SIGNERS_OVER_REGION_CAP in report.reasons
    assert "aws:us-east-1" in report.over_region_cap_regions


def test_exactly_two_signers_per_region_is_ok():
    # The cap is 2, not 1.
    report = verify_signer_provenance([
        _att("kA", "h-aws-1", "aws:us-east-1"),
        _att("kB", "h-aws-2", "aws:us-east-1"),
        _att("kC", "h-gcp-1", "gcp:europe-west-4"),
    ])
    assert report.is_allowed


# ---------------------------------------------------------------------------
# Missing-attestation refusal
# ---------------------------------------------------------------------------

def test_missing_host_id_refused():
    report = verify_signer_provenance([
        _att("kA", None, "aws:us-east-1"),
        _att("kB", "h-gcp-1", "gcp:europe-west-4"),
        _att("kC", "h-hetzner-1", "hetzner:fsn1"),
    ])
    assert not report.is_allowed
    assert REASON_MISSING_ATTESTATION in report.reasons
    assert "kA" in report.missing_attestation


def test_missing_region_refused():
    report = verify_signer_provenance([
        _att("kA", "h-aws-1", None),
        _att("kB", "h-gcp-1", "gcp:europe-west-4"),
        _att("kC", "h-hetzner-1", "hetzner:fsn1"),
    ])
    assert not report.is_allowed
    assert REASON_MISSING_ATTESTATION in report.reasons


def test_empty_strings_treated_as_missing():
    report = verify_signer_provenance([
        _att("kA", "", "aws:us-east-1"),
        _att("kB", "h-gcp-1", ""),
        _att("kC", "h-hetzner-1", "hetzner:fsn1"),
    ])
    assert not report.is_allowed
    assert REASON_MISSING_ATTESTATION in report.reasons
    assert "kA" in report.missing_attestation
    assert "kB" in report.missing_attestation


# ---------------------------------------------------------------------------
# Distinct-host floor
# ---------------------------------------------------------------------------

def test_below_threshold_distinct_hosts_refused():
    # Only two distinct hosts but threshold is 3.
    report = verify_signer_provenance([
        _att("kA", "h-aws-1", "aws:us-east-1"),
        _att("kB", "h-gcp-1", "gcp:europe-west-4"),
    ])
    assert not report.is_allowed
    assert REASON_INSUFFICIENT_DISTINCT_HOSTS in report.reasons
    assert report.distinct_hosts == 2


# ---------------------------------------------------------------------------
# Compound violations
# ---------------------------------------------------------------------------

def test_multiple_violations_reported_together():
    # Missing attestation AND a shared host between the remaining two.
    report = verify_signer_provenance([
        _att("kA", None, None),
        _att("kB", "h-aws-1", "aws:us-east-1"),
        _att("kC", "h-aws-1", "aws:us-east-1"),
    ])
    assert not report.is_allowed
    assert REASON_MISSING_ATTESTATION in report.reasons
    assert REASON_SIGNERS_SHARE_HOST in report.reasons


# ---------------------------------------------------------------------------
# Enforcement wrapper
# ---------------------------------------------------------------------------

def test_enforce_returns_report_on_healthy_set():
    report = enforce_signer_provenance([
        _att("kA", "h-aws-1", "aws:us-east-1"),
        _att("kB", "h-gcp-1", "gcp:europe-west-4"),
        _att("kC", "h-hetzner-1", "hetzner:fsn1"),
    ])
    assert report.is_allowed


def test_enforce_raises_on_shared_host():
    with pytest.raises(SignerProvenanceError) as excinfo:
        enforce_signer_provenance([
            _att("kA", "h-shared", "aws:us-east-1"),
            _att("kB", "h-shared", "aws:us-east-1"),
            _att("kC", "h-gcp-1", "gcp:europe-west-4"),
        ])
    assert "FHS-2" in str(excinfo.value)
    assert "h-shared" in excinfo.value.report.over_host_cap_hosts


# ---------------------------------------------------------------------------
# Audit scenario — the exact attack the gate exists for
# ---------------------------------------------------------------------------

def test_audit_scenario_one_physical_machine_two_hsms_refused():
    # Path 1 sub-leaf 1b: attacker has compromised ONE physical
    # machine that hosts TWO cluster HSMs. On-chain
    # `verify_threshold_signatures` deduplicates by pubkey, but both
    # signatures are over the canonical digest under distinct
    # cluster pubkeys — the on-chain check passes. FHS-2 catches it
    # at the provenance layer: both signatures share host_id.
    with pytest.raises(SignerProvenanceError) as excinfo:
        enforce_signer_provenance([
            _att("kA", "ec2-i-0xdeadbeef", "aws:us-east-1"),
            _att("kB", "ec2-i-0xdeadbeef", "aws:us-east-1"),  # same machine
            _att("kC", "h-gcp-honest",     "gcp:europe-west-4"),
        ])
    report = excinfo.value.report
    assert REASON_SIGNERS_SHARE_HOST in report.reasons
    assert "ec2-i-0xdeadbeef" in report.over_host_cap_hosts
