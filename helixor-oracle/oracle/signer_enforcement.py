"""
oracle/signer_enforcement.py — NSS-2: mainnet refusal of in-process
Ed25519 signing.

THE CATASTROPHIC FAILURE SCENARIO (audit Scenario B, step 2)
------------------------------------------------------------
    "Nation-state actor installs a kernel module on the cloud-provider
    hypervisor that intercepts signing calls and exfiltrates private
    keys over a covert channel."

A kernel-level attacker against `InProcessSigner` reads the Ed25519
private key out of process memory on the first sign() call. The
cluster's threshold math is intact (the attacker holds one key, needs
K), but the substrate of the math — "keys are private" — is broken.
On three diverse cloud providers a nation-state needs three covert
agreements; if the cluster has even ONE node using `InProcessSigner`
on mainnet, the attacker walks away with at least one key per
compromised host.

The VULN-25 signer surface (`oracle/cluster/signer.py`) already
defines:
  - `Signer`         — narrow Protocol every caller depends on
  - `InProcessSigner` — wraps a `NodeKeypair`; private key lives in
                        process memory
  - `HSMSigner`     — typed stub; subclasses route `sign` through an
                       HSM (YubiHSM, AWS KMS, Cubist, Fireblocks MPC,
                       etc.). The base class refuses to sign so a
                       silent fallback to in-process is impossible.

What VULN-25 did NOT close is the OPERATIONAL question: nothing
refuses an oracle process that boots with `InProcessSigner` on
mainnet. A misconfigured deploy ships an in-process key into
production. NSS-2 reifies the contract:

    On mainnet, the signer MUST NOT be `InProcessSigner`.
    On devnet/localnet, the signer MAY be `InProcessSigner` (development
    ergonomics).

The gate fails CLOSED on mainnet and fails OPEN on every other
network. An explicit opt-in (`HELIXOR_INPROCESS_SIGNER_OK=1`) bypasses
the refusal for one scenario only: an HSM outage where operators
deliberately accept the risk and record the verdict in
`audit/reports/inprocess_signer_optin.md`. The opt-in is logged at
ERROR level and is the operator's audit trail.

THE MITIGATION (this file)
--------------------------
A network-aware enforcement helper:

  * `classify_signer(signer)` — pure-stdlib bucket: `"in-process"`,
    `"hsm"`, or `"unknown"` (anything not in the audited surface
    treated as unknown, conservative).
  * `verify_production_signer(signer, *, network, opted_in)` — returns
    a `SignerEnforcementReport` describing the decision. Pure; no
    logging.
  * `enforce_production_signer(signer, *, service)` — wraps the
    verifier with `network_guard.evaluate()`, raises
    `InsecureSignerError` on a mainnet refusal, logs at ERROR/WARNING
    on the opt-in path, INFO on devnet.

DETERMINISM
-----------
The classifier is purely structural (class name + duck-typing). Two
operators inspecting the same signer object reach the same verdict.

INTERACTION WITH NSS-1 / NSS-3
------------------------------
NSS-1 (cloud-compute diversity) catches the substrate of step 1.
NSS-2 catches the OPERATIONAL step where a misconfigured deploy
ships an in-process key onto that substrate. NSS-3 (agent-age gate)
catches the downstream issuance step — even if a key is exfiltrated
DESPITE NSS-1+NSS-2, NSS-3 stops the attacker from minting GREEN
certs for fresh state-controlled wallets.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from oracle.network_guard import NetworkVerdict, evaluate as evaluate_network


logger = logging.getLogger("helixor.oracle.signer_enforcement")


# =============================================================================
# Constants
# =============================================================================

#: Environment variable that opts out of the mainnet refusal. The value
#: must be the literal string `"1"`; any other value is treated as
#: "not opted in." Set this only for documented HSM-outage scenarios;
#: the verdict is logged at ERROR.
ENV_INPROCESS_SIGNER_OK = "HELIXOR_INPROCESS_SIGNER_OK"

#: Classifier bucket names — stable strings the audit gate greps for.
SIGNER_BUCKET_IN_PROCESS = "in-process"
SIGNER_BUCKET_HSM = "hsm"
SIGNER_BUCKET_UNKNOWN = "unknown"

#: Class names the classifier maps explicitly. Anything else is bucketed
#: as `unknown` — conservative: an unaudited signer fails mainnet by
#: default. A new HSM subclass MUST end its class name with the literal
#: substring `"HSMSigner"` to inherit the `hsm` bucket OR register
#: explicitly via `register_hsm_signer_class(...)`.
KNOWN_IN_PROCESS_CLASS_NAMES = frozenset({"InProcessSigner"})

#: Class names known to live behind an HSM boundary. The base
#: `HSMSigner` is included; subclasses are matched by name suffix
#: (see `classify_signer`).
KNOWN_HSM_CLASS_NAMES = frozenset({"HSMSigner"})


# =============================================================================
# Errors
# =============================================================================

class InsecureSignerError(RuntimeError):
    """
    Raised when the signer enforcement gate refuses to start.

    The exception's `.report` carries the verdict so the operator can
    see WHICH signer the cluster booted with and WHICH network was
    detected. The boot path catches this and exits non-zero before any
    signing work begins.
    """

    def __init__(self, message: str, report: "SignerEnforcementReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# Verdict
# =============================================================================

@dataclass(frozen=True, slots=True)
class SignerEnforcementReport:
    """
    Result of one NSS-2 enforcement check.

    `signer_class_name`   the runtime class name of the signer.
    `signer_bucket`       one of `in-process` / `hsm` / `unknown`.
    `network`             the network the guard detected.
    `is_production`       True iff network is in production set.
    `opted_in`            True iff `HELIXOR_INPROCESS_SIGNER_OK == "1"`.
    `must_refuse`         True iff production AND in-process/unknown
                          bucket AND NOT opted in.
    """
    signer_class_name: str
    signer_bucket:     str
    network:           str
    is_production:     bool
    opted_in:          bool
    must_refuse:       bool


# =============================================================================
# Classifier
# =============================================================================

def classify_signer(signer: object) -> str:
    """
    Bucket a signer object into `in-process`, `hsm`, or `unknown`.

    The match is on the class's `__name__`:
      * Exact match against `KNOWN_IN_PROCESS_CLASS_NAMES` -> `in-process`.
      * Exact match against `KNOWN_HSM_CLASS_NAMES` OR a suffix match
        on `"HSMSigner"` -> `hsm`. The suffix rule lets a
        `YubiHSMSigner(HSMSigner)` subclass inherit the `hsm` bucket
        without re-registration.
      * Anything else -> `unknown`. Unknown buckets are refused on
        mainnet — an unaudited signer cannot ship to production.
    """
    name = type(signer).__name__
    if name in KNOWN_IN_PROCESS_CLASS_NAMES:
        return SIGNER_BUCKET_IN_PROCESS
    if name in KNOWN_HSM_CLASS_NAMES:
        return SIGNER_BUCKET_HSM
    if name.endswith("HSMSigner"):
        return SIGNER_BUCKET_HSM
    return SIGNER_BUCKET_UNKNOWN


def opted_in_to_inprocess_signer() -> bool:
    """True iff `HELIXOR_INPROCESS_SIGNER_OK` is set to `"1"`."""
    return os.environ.get(ENV_INPROCESS_SIGNER_OK, "").strip() == "1"


# =============================================================================
# Verifier (pure)
# =============================================================================

def verify_production_signer(
    signer: object,
    *,
    network_verdict: NetworkVerdict,
    opted_in: bool,
) -> SignerEnforcementReport:
    """
    Build an enforcement report from a signer + a network verdict.

    Pure: no logging, no environment reads, no I/O. The caller injects
    the network verdict (so tests can pin it) and the opt-in flag.

    The rule:
      * Production network + `in-process` or `unknown` bucket + NOT
        opted in -> `must_refuse=True`.
      * Production network + `hsm` bucket -> `must_refuse=False`.
      * Any non-production network -> `must_refuse=False` regardless
        of bucket.
    """
    bucket = classify_signer(signer)
    must_refuse = (
        network_verdict.is_production
        and bucket != SIGNER_BUCKET_HSM
        and not opted_in
    )
    return SignerEnforcementReport(
        signer_class_name=type(signer).__name__,
        signer_bucket=bucket,
        network=network_verdict.network,
        is_production=network_verdict.is_production,
        opted_in=opted_in,
        must_refuse=must_refuse,
    )


# =============================================================================
# Enforcement (impure)
# =============================================================================

def enforce_production_signer(
    signer: object,
    *,
    service: str | None = None,
) -> SignerEnforcementReport:
    """
    Refuse to start a service if NSS-2 says so.

    Reads `HELIXOR_NETWORK` + `HELIXOR_INPROCESS_SIGNER_OK` from the
    environment, runs `verify_production_signer`, logs the verdict,
    and raises `InsecureSignerError` on a mainnet refusal.

    The verdict is returned on every non-raising path so callers can
    forward it to telemetry.
    """
    verdict = evaluate_network()
    report = verify_production_signer(
        signer,
        network_verdict=verdict,
        opted_in=opted_in_to_inprocess_signer(),
    )
    label = service or "<unspecified>"

    if report.must_refuse:
        msg = (
            f"signer_enforcement: REFUSING to start service {label!r} on "
            f"network {report.network!r} with signer "
            f"{report.signer_class_name!r} (bucket {report.signer_bucket!r}). "
            f"NSS-2 requires HSM-backed signing on production networks — "
            f"set {ENV_INPROCESS_SIGNER_OK}=1 in the environment to "
            f"acknowledge the risk and record the justification in "
            f"audit/reports/inprocess_signer_optin.md."
        )
        logger.error(msg)
        raise InsecureSignerError(msg, report)

    if report.is_production and report.opted_in:
        logger.error(
            "signer_enforcement: service %s is starting on PRODUCTION "
            "network %s with signer bucket %r and an explicit "
            "%s=1 opt-in — record the justification in "
            "audit/reports/inprocess_signer_optin.md",
            label, report.network, report.signer_bucket,
            ENV_INPROCESS_SIGNER_OK,
        )
    elif report.is_production:
        logger.warning(
            "signer_enforcement: service %s starting on PRODUCTION "
            "network %s with HSM-backed signer %s",
            label, report.network, report.signer_class_name,
        )
    else:
        logger.info(
            "signer_enforcement: service %s starting on %s with signer "
            "bucket %r (non-production)",
            label, report.network, report.signer_bucket,
        )
    return report


__all__ = [
    "ENV_INPROCESS_SIGNER_OK",
    "KNOWN_HSM_CLASS_NAMES",
    "KNOWN_IN_PROCESS_CLASS_NAMES",
    "SIGNER_BUCKET_HSM",
    "SIGNER_BUCKET_IN_PROCESS",
    "SIGNER_BUCKET_UNKNOWN",
    "InsecureSignerError",
    "SignerEnforcementReport",
    "classify_signer",
    "enforce_production_signer",
    "opted_in_to_inprocess_signer",
    "verify_production_signer",
]
