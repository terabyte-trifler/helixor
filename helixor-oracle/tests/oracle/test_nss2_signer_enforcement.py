"""
tests/oracle/test_nss2_signer_enforcement.py — NSS-2 mainnet signer
enforcement gate.

Pins:
  - Classifier buckets (InProcessSigner -> in-process, HSMSigner -> hsm,
    unknown subclass -> unknown, HSMSigner-suffixed subclass -> hsm).
  - Pure verifier: production network + in-process -> must_refuse.
  - Pure verifier: production network + HSM -> NOT refused.
  - Pure verifier: production network + in-process + opt-in -> NOT
    refused (the opt-in path).
  - Pure verifier: devnet/localnet always passes regardless of bucket.
  - Enforcement raises InsecureSignerError on mainnet+in-process.
  - Enforcement returns report on every non-raising path.
  - Audit-scenario: an exfiltrated InProcessSigner on mainnet is
    refused with the report attached.
"""

from __future__ import annotations

import logging

import pytest

from oracle.cluster.signer import HSMSigner, InProcessSigner
from oracle.network_guard import NetworkVerdict
from oracle.signer_enforcement import (
    ENV_INPROCESS_SIGNER_OK,
    SIGNER_BUCKET_HSM,
    SIGNER_BUCKET_IN_PROCESS,
    SIGNER_BUCKET_UNKNOWN,
    InsecureSignerError,
    classify_signer,
    enforce_production_signer,
    verify_production_signer,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

class _Keypair:
    """Stub keypair satisfying the InProcessSigner duck-type."""

    def __init__(self) -> None:
        self.public_key = b"\x01" * 32

    def sign(self, message: bytes) -> bytes:  # noqa: ARG002
        return b"\x00" * 64


class _StubHSM(HSMSigner):
    """An audited HSM subclass that goes through a fake HSM."""

    def sign(self, message: bytes) -> bytes:  # noqa: ARG002
        return b"\x42" * 64


class _StealthYubiHSMSigner(HSMSigner):
    """A subclass whose name ends with HSMSigner — should bucket as hsm."""

    def sign(self, message: bytes) -> bytes:  # noqa: ARG002
        return b"\x43" * 64


class _MysterySigner:
    """An unaudited shape — must bucket as unknown."""

    def __init__(self) -> None:
        self.public_key = b"\x02" * 32

    def sign(self, message: bytes) -> bytes:  # noqa: ARG002
        return b"\x99" * 64


def _verdict(network: str, *, opted_in: bool = False) -> NetworkVerdict:
    return NetworkVerdict(
        network=network,
        is_production=network in {"mainnet", "mainnet-beta"},
        opted_in=opted_in,
    )


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

def test_classify_in_process_signer():
    assert classify_signer(InProcessSigner(_Keypair())) == SIGNER_BUCKET_IN_PROCESS


def test_classify_hsm_base_class():
    assert classify_signer(HSMSigner(b"\x01" * 32)) == SIGNER_BUCKET_HSM


def test_classify_subclass_without_hsmsigner_suffix_is_unknown():
    # `_StubHSM` is an HSM-derived class but its NAME does not end in
    # `HSMSigner`, so the classifier buckets it as `unknown` —
    # conservative: subclasses must declare HSM-ness in their name to
    # inherit the bucket.
    assert classify_signer(_StubHSM(b"\x02" * 32)) == SIGNER_BUCKET_UNKNOWN


def test_classify_hsm_subclass_by_suffix_rule():
    # Subclasses whose class name ends with `HSMSigner` inherit the
    # `hsm` bucket so a `YubiHSMSigner(HSMSigner)` does NOT need an
    # entry in KNOWN_HSM_CLASS_NAMES.
    assert classify_signer(_StealthYubiHSMSigner(b"\x03" * 32)) == SIGNER_BUCKET_HSM


def test_classify_unaudited_signer_is_unknown():
    assert classify_signer(_MysterySigner()) == SIGNER_BUCKET_UNKNOWN


# ---------------------------------------------------------------------------
# Pure verifier
# ---------------------------------------------------------------------------

def test_mainnet_inprocess_must_refuse():
    report = verify_production_signer(
        InProcessSigner(_Keypair()),
        network_verdict=_verdict("mainnet"),
        opted_in=False,
    )
    assert report.must_refuse
    assert report.signer_bucket == SIGNER_BUCKET_IN_PROCESS


def test_mainnet_hsm_passes():
    report = verify_production_signer(
        _StealthYubiHSMSigner(b"\x04" * 32),
        network_verdict=_verdict("mainnet"),
        opted_in=False,
    )
    assert not report.must_refuse
    assert report.signer_bucket == SIGNER_BUCKET_HSM


def test_mainnet_unknown_must_refuse():
    # An unaudited signer is treated as in-process-equivalent on mainnet.
    report = verify_production_signer(
        _MysterySigner(),
        network_verdict=_verdict("mainnet"),
        opted_in=False,
    )
    assert report.must_refuse
    assert report.signer_bucket == SIGNER_BUCKET_UNKNOWN


def test_mainnet_inprocess_with_explicit_optin_passes():
    report = verify_production_signer(
        InProcessSigner(_Keypair()),
        network_verdict=_verdict("mainnet"),
        opted_in=True,
    )
    assert not report.must_refuse
    assert report.opted_in


def test_devnet_inprocess_passes():
    report = verify_production_signer(
        InProcessSigner(_Keypair()),
        network_verdict=_verdict("devnet"),
        opted_in=False,
    )
    assert not report.must_refuse


def test_localnet_unknown_passes():
    # Developer ergonomics — dev path doesn't refuse exotic signers.
    report = verify_production_signer(
        _MysterySigner(),
        network_verdict=_verdict("localnet"),
        opted_in=False,
    )
    assert not report.must_refuse


def test_mainnet_beta_treated_as_production():
    report = verify_production_signer(
        InProcessSigner(_Keypair()),
        network_verdict=_verdict("mainnet-beta"),
        opted_in=False,
    )
    assert report.must_refuse


# ---------------------------------------------------------------------------
# Enforcement wrapper — driven by env
# ---------------------------------------------------------------------------

def test_enforce_raises_on_mainnet_inprocess(monkeypatch):
    # `mainnet-beta` is the only production label the network guard
    # recognises (`network_guard.PRODUCTION_NETWORKS`).
    monkeypatch.setenv("HELIXOR_NETWORK", "mainnet-beta")
    monkeypatch.delenv(ENV_INPROCESS_SIGNER_OK, raising=False)
    with pytest.raises(InsecureSignerError) as excinfo:
        enforce_production_signer(
            InProcessSigner(_Keypair()), service="oracle-node:0",
        )
    assert excinfo.value.report.must_refuse
    assert excinfo.value.report.signer_bucket == SIGNER_BUCKET_IN_PROCESS
    assert "NSS-2" in str(excinfo.value)


def test_enforce_passes_on_mainnet_with_optin(monkeypatch, caplog):
    monkeypatch.setenv("HELIXOR_NETWORK", "mainnet-beta")
    monkeypatch.setenv(ENV_INPROCESS_SIGNER_OK, "1")
    with caplog.at_level(logging.ERROR, logger="helixor.oracle.signer_enforcement"):
        report = enforce_production_signer(
            InProcessSigner(_Keypair()), service="oracle-node:0",
        )
    assert not report.must_refuse
    # The opt-in path MUST log at ERROR so the operator sees the
    # decision in the journal.
    assert any(
        "explicit" in record.message and "opt-in" in record.message
        for record in caplog.records
    )


def test_enforce_passes_on_devnet_in_process(monkeypatch):
    monkeypatch.setenv("HELIXOR_NETWORK", "devnet")
    monkeypatch.delenv(ENV_INPROCESS_SIGNER_OK, raising=False)
    report = enforce_production_signer(
        InProcessSigner(_Keypair()), service="oracle-node:test",
    )
    assert not report.must_refuse


def test_enforce_passes_on_mainnet_with_hsm(monkeypatch):
    monkeypatch.setenv("HELIXOR_NETWORK", "mainnet-beta")
    monkeypatch.delenv(ENV_INPROCESS_SIGNER_OK, raising=False)
    report = enforce_production_signer(
        _StealthYubiHSMSigner(b"\x05" * 32), service="oracle-node:0",
    )
    assert not report.must_refuse
    assert report.signer_bucket == SIGNER_BUCKET_HSM


# ---------------------------------------------------------------------------
# Audit scenario
# ---------------------------------------------------------------------------

def test_audit_scenario_b_step2_caught(monkeypatch):
    # Scenario B step 2: a kernel module on the cloud host could
    # exfiltrate any private key sitting in process memory. NSS-2
    # refuses to start a mainnet node that would expose the key in
    # the first place — the substrate of the attack is not present.
    monkeypatch.setenv("HELIXOR_NETWORK", "mainnet-beta")
    monkeypatch.delenv(ENV_INPROCESS_SIGNER_OK, raising=False)
    with pytest.raises(InsecureSignerError) as excinfo:
        enforce_production_signer(
            InProcessSigner(_Keypair()), service="oracle-node:prod",
        )
    # The verdict shows the operator exactly which signer they shipped
    # and which network the guard detected.
    assert excinfo.value.report.signer_class_name == "InProcessSigner"
    assert excinfo.value.report.network == "mainnet-beta"
