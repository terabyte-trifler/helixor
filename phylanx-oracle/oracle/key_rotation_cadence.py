"""
oracle/key_rotation_cadence.py — FHS-1: cluster-key rotation cadence
floor for red-team Path 1 sub-leaf 1a ("Compromise 3 oracle keys").

THE ATTACK PATH (Forge-High-Score-Cert Path 1, sub-leaf 1a)
-----------------------------------------------------------
The 3-of-5 threshold makes a "compromise 3 oracle keys" attack HIGH
EFFORT in expectation: NSS-1 forces the nodes onto >= 2 distinct
clouds, NSS-2 forces every key into an HSM. But a SUCCESSFUL
compromise of K keys is PERMANENT under the current `OracleConfig`
contract — once an attacker holds the keys, they remain valid for
the lifetime of the cluster, and the attacker can wait MONTHS for
the right moment to forge a cert. The HIGH-EFFORT label only bounds
the effort PER COMPROMISE, not the value extractable once
compromised.

FHS-1 closes the dwell-time substrate: every cluster key carries a
`birth_unix`, and verification refuses any key whose age exceeds
`MAX_KEY_AGE_SECONDS = 90 * 24 * 3600` (90 days). A compromised key
that the attacker tries to keep silent for ~3 months becomes
structurally invalid, forcing the attacker to re-compromise on every
rotation cycle. Combined with the rotation overlap guard (FHS-3),
this turns a one-shot key compromise into a continuously expensive
campaign.

CALIBRATION
-----------
- `MAX_KEY_AGE_SECONDS = 90 * 24 * 3600` (90 days) — the hard
  rotation floor. Past this point a key is REFUSED.
- `WARN_KEY_AGE_SECONDS = 60 * 24 * 3600` (60 days) — operators are
  warned 30 days before the floor. Rotation ceremonies under FHS-3
  take 48h (the propose/attest/enact timelock from VULN-13's
  pending_oracle_rotation), so a 30-day warning window leaves ample
  time for orderly rotation even if a key holder is on vacation.
- `CADENCE_FUTURE_TOLERANCE_SECONDS = 60` — a single epoch's worth
  of clock skew. A key whose `birth_unix` is more than 60s in the
  future is structurally suspect (forged or misconfigured) and is
  REFUSED with `KEY_BIRTH_IN_FUTURE`.

INTERACTION WITH NSS-1 / NSS-2 / FHS-3 / VULN-13
------------------------------------------------
- NSS-1 (`cloud_diversity.py`) forces nodes onto >= 2 clouds — closes
  the SINGLE-CLOUD-CAPTURE substrate of the 3-key compromise.
- NSS-2 (`signer_enforcement.py`) refuses in-process Ed25519 signers
  on mainnet — closes the IN-MEMORY-EXFIL substrate.
- FHS-1 (this module) refuses keys past `MAX_KEY_AGE_SECONDS` —
  closes the PERMANENT-COMPROMISE substrate.
- FHS-3 (`rotation_overlap_guard.py`) limits each rotation to at most
  one key replaced — closes the WHOLESALE-REPLACEMENT substrate.
- VULN-13's `pending_oracle_rotation.rs` enforces the 48h on-chain
  timelock + N-of-M attestation — this module is the OFF-CHAIN
  pre-flight that operators wire BEFORE proposing the rotation.

DETERMINISM
-----------
Pure stdlib. Integer arithmetic on `(birth_unix, current_unix)` per
key. No clock, no network, no randomness.
"""

from __future__ import annotations

from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: Hard rotation floor — any cluster key older than this is REFUSED.
#: 90 days at the on-chain epoch cadence of 2h = 1080 epochs.
MAX_KEY_AGE_SECONDS = 90 * 24 * 3600

#: Soft warning threshold — operators are nudged toward rotation
#: 30 days before the hard floor.
WARN_KEY_AGE_SECONDS = 60 * 24 * 3600

#: Seconds of future-skew tolerance for `birth_unix > current_unix`.
CADENCE_FUTURE_TOLERANCE_SECONDS = 60

#: Status labels. Stable strings the operator runbook + audit gate
#: grep for.
CADENCE_OK = "OK"
CADENCE_WARN = "WARN"
CADENCE_OVERDUE = "OVERDUE"

#: Reason codes — stable strings the consumer logs and the audit gate
#: cross-references.
REASON_KEY_NEAR_ROTATION_FLOOR = "KEY_NEAR_ROTATION_FLOOR"
REASON_KEY_PAST_ROTATION_FLOOR = "KEY_PAST_ROTATION_FLOOR"
REASON_KEY_BIRTH_IN_FUTURE = "KEY_BIRTH_IN_FUTURE"


# =============================================================================
# Errors
# =============================================================================

class KeyRotationOverdueError(RuntimeError):
    """
    Raised by `enforce_key_rotation_cadence` when at least one cluster
    key is past `MAX_KEY_AGE_SECONDS`.

    `.report` carries the per-key verdicts so the operator can target
    the rotation ceremony at the specific overdue keys (the VULN-13
    propose/attest/enact flow rotates one key at a time per FHS-3).
    """

    def __init__(self, message: str, report: "KeyRotationReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class ClusterKeySnapshot:
    """
    One cluster key's identity + birth.

    `pubkey`     stable string identity (base58 in production; opaque
                 string elsewhere — verifier does not interpret).
    `birth_unix` Unix seconds at which the key first joined the
                 active cluster (the `enact` slot of the most recent
                 VULN-13 rotation ceremony that introduced this key,
                 or the cluster bootstrap timestamp for genesis keys).
    """
    pubkey:     str
    birth_unix: int


@dataclass(frozen=True, slots=True)
class KeyAgeVerdict:
    """
    Per-key cadence verdict.

    `pubkey`           echoed from the input.
    `age_seconds`      current_unix - birth_unix, clamped to 0 on
                       small skew; the special value 0 also covers
                       future-dated keys (see `reasons`).
    `status`           CADENCE_OK / WARN / OVERDUE.
    `reasons`          reason codes; empty when OK.
    """
    pubkey:      str
    age_seconds: int
    status:      str
    reasons:     tuple[str, ...]


@dataclass(frozen=True, slots=True)
class KeyRotationReport:
    """
    Verdict of one FHS-1 check.

    `verdicts`         per-key results.
    `warn_seconds`     echoed from constants.
    `max_age_seconds`  echoed from constants.
    `is_allowed`       True iff no key is OVERDUE.
    """
    verdicts:        tuple[KeyAgeVerdict, ...]
    warn_seconds:    int
    max_age_seconds: int

    @property
    def is_allowed(self) -> bool:
        return not any(v.status == CADENCE_OVERDUE for v in self.verdicts)

    @property
    def overdue_keys(self) -> tuple[str, ...]:
        return tuple(
            v.pubkey for v in self.verdicts if v.status == CADENCE_OVERDUE
        )

    @property
    def warning_keys(self) -> tuple[str, ...]:
        return tuple(
            v.pubkey for v in self.verdicts if v.status == CADENCE_WARN
        )


# =============================================================================
# Verifier (pure)
# =============================================================================

def verify_key_rotation_cadence(
    cluster_keys: tuple[ClusterKeySnapshot, ...] | list[ClusterKeySnapshot],
    *,
    current_unix: int,
) -> KeyRotationReport:
    """
    Compute per-key cadence verdicts.

    The rule (per key):
      * `birth_unix > current_unix + CADENCE_FUTURE_TOLERANCE_SECONDS`
        -> OVERDUE, reason KEY_BIRTH_IN_FUTURE (age clamped to 0).
      * `age_seconds > MAX_KEY_AGE_SECONDS` -> OVERDUE, reason
        KEY_PAST_ROTATION_FLOOR.
      * `age_seconds > WARN_KEY_AGE_SECONDS` -> WARN, reason
        KEY_NEAR_ROTATION_FLOOR.
      * else -> OK.

    Inclusive boundary: `age_seconds == MAX_KEY_AGE_SECONDS` is OK
    (exactly at the floor is still acceptable); strictly past is
    OVERDUE.

    Pure: no logging, no environment reads, no I/O.
    """
    verdicts: list[KeyAgeVerdict] = []
    for key in cluster_keys:
        delta = current_unix - key.birth_unix
        if delta < -CADENCE_FUTURE_TOLERANCE_SECONDS:
            verdicts.append(KeyAgeVerdict(
                pubkey=key.pubkey,
                age_seconds=0,
                status=CADENCE_OVERDUE,
                reasons=(REASON_KEY_BIRTH_IN_FUTURE,),
            ))
            continue

        age = max(delta, 0)
        if age > MAX_KEY_AGE_SECONDS:
            verdicts.append(KeyAgeVerdict(
                pubkey=key.pubkey,
                age_seconds=age,
                status=CADENCE_OVERDUE,
                reasons=(REASON_KEY_PAST_ROTATION_FLOOR,),
            ))
        elif age > WARN_KEY_AGE_SECONDS:
            verdicts.append(KeyAgeVerdict(
                pubkey=key.pubkey,
                age_seconds=age,
                status=CADENCE_WARN,
                reasons=(REASON_KEY_NEAR_ROTATION_FLOOR,),
            ))
        else:
            verdicts.append(KeyAgeVerdict(
                pubkey=key.pubkey,
                age_seconds=age,
                status=CADENCE_OK,
                reasons=(),
            ))

    return KeyRotationReport(
        verdicts=tuple(verdicts),
        warn_seconds=WARN_KEY_AGE_SECONDS,
        max_age_seconds=MAX_KEY_AGE_SECONDS,
    )


# =============================================================================
# Enforcement (fail-closed wrapper)
# =============================================================================

def enforce_key_rotation_cadence(
    cluster_keys: tuple[ClusterKeySnapshot, ...] | list[ClusterKeySnapshot],
    *,
    current_unix: int,
) -> KeyRotationReport:
    """
    Run `verify_key_rotation_cadence` and raise on any OVERDUE key.

    Returns the report when every key is OK or WARN. Raises
    `KeyRotationOverdueError` when at least one key has crossed the
    `MAX_KEY_AGE_SECONDS` floor — the cluster's operators must
    propose+enact a VULN-13 rotation ceremony before this module will
    accept the topology again.
    """
    report = verify_key_rotation_cadence(
        cluster_keys, current_unix=current_unix,
    )
    if report.is_allowed:
        return report
    raise KeyRotationOverdueError(
        f"FHS-1: cluster keys past the {MAX_KEY_AGE_SECONDS}s "
        f"rotation floor — overdue={list(report.overdue_keys)!r}. "
        f"A compromised key past this age has had ~90 days of "
        f"silent dwell time; rotate via the VULN-13 propose/attest/"
        f"enact ceremony before continuing.",
        report,
    )


__all__ = [
    "CADENCE_FUTURE_TOLERANCE_SECONDS",
    "CADENCE_OK",
    "CADENCE_OVERDUE",
    "CADENCE_WARN",
    "ClusterKeySnapshot",
    "KeyAgeVerdict",
    "KeyRotationOverdueError",
    "KeyRotationReport",
    "MAX_KEY_AGE_SECONDS",
    "REASON_KEY_BIRTH_IN_FUTURE",
    "REASON_KEY_NEAR_ROTATION_FLOOR",
    "REASON_KEY_PAST_ROTATION_FLOOR",
    "WARN_KEY_AGE_SECONDS",
    "enforce_key_rotation_cadence",
    "verify_key_rotation_cadence",
]
