"""
oracle/cert_refusal_log.py — OFAC-1: real-time silent-delist transparency.

THE HIDDEN CENSORSHIP RISK (audit)
----------------------------------
    "A nation-state could pressure oracle node operators to delist
    certain agent wallets."

The cluster's existing defenses against state-pressure delisting are
strong but RETROSPECTIVE:

  * HCR-4 (`operator_manifest.py`) requires ≥2 distinct jurisdictions
    so a single legal process cannot reach every signer.
  * 3-of-5 threshold signing makes a single coerced node insufficient
    to delist an agent.
  * `HealthCertificate` PDAs are write-once, so an auditor can later
    notice that agent X used to receive certs and then suddenly
    stopped.

But the audit's response strategy needs more than retrospective
visibility: it needs REAL-TIME signal that the cluster considered an
agent and DECLINED to issue. Today, every per-agent gate
(`agent_age_gate`, `cert_reissue_cadence`, `score_velocity`,
`score_drift_ceiling`, the input-commitment consensus check in
`cluster/pipeline.py`, and the quorum-miss path in
`cluster/aggregation.py`) raises a typed exception or returns a
refusal report — but nothing publishes that fact onto the bus. A
captured cluster that quietly refuses to score an OFAC-sanctioned
agent (or any agent) is invisible until the absence is noticed.

THIS MODULE — what it does
--------------------------
Defines the substrate for a structured, append-only refusal log that
every per-agent gate site emits into. The log itself is a thin
collector — pure Python, no I/O — that the oracle's per-epoch
issuance loop drains to the indexer's Kafka bus at end-of-epoch (the
new `Topic.CERT_REFUSED = "agent.cert_events.refused"` topic).

The wire schema is intentionally narrow:

  agent_wallet, epoch, requested_tier, reason_codes, gate, detected_at

`reason_codes` is the stable string set already exported by each
gate (`REASON_SECONDS_TOO_YOUNG`, `REASON_DELTA`, etc.). `gate` is
one of `RefusalGate` — a closed enum naming WHICH defense fired, so
an auditor reading the topic can immediately attribute the refusal.

WHAT THIS MODULE DOES NOT DO
----------------------------
It does NOT decide whether a refusal is censorship-vs-correct-policy.
NSS-3 refusing GREEN on a 13-day-old wallet is a CORRECT refusal,
not censorship. The audit gate (`audit/cert_refusal_check.py`) reads
the topic AFTER THE FACT and flags suspicious patterns (e.g., the
same agent_wallet refused with `OPERATOR_OVERRIDE` reason, or the
refusal rate for one jurisdiction-tagged agent set spikes 10x while
peers stay flat). The substrate is *transparency*, not *policy*.

It also does NOT change any existing gate's behaviour. Each gate
still raises the same typed exception when it refuses; this module
adds an OPTIONAL collector hook that the per-epoch issuance loop can
pass in. A gate called without a collector behaves exactly as
before. This keeps the change strictly additive and unit-testable in
isolation.

DETERMINISM
-----------
Pure stdlib. No clock (each `record(...)` carries its own
`detected_at`), no randomness, no network. The collector's
`drain()` returns refusals in record-order, so two operators
running the gate on the same input produce byte-identical drains.
"""

from __future__ import annotations

import enum
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone


# =============================================================================
# Reason codes — stable strings the audit gate greps for.
# =============================================================================
#
# These mirror the codes the per-gate modules already export.
# Re-exporting them here gives the audit a SINGLE import surface
# (`from oracle.cert_refusal_log import RefusalReason`) so a future
# code search for "where do refusal codes live" finds one file.

class RefusalReason(str, enum.Enum):
    """Stable refusal reason codes, mirrored from the per-gate modules."""

    # NSS-3 — agent_age_gate.py
    AGENT_SECONDS_TOO_YOUNG       = "AGENT_SECONDS_TOO_YOUNG"
    AGENT_EPOCHS_TOO_YOUNG        = "AGENT_EPOCHS_TOO_YOUNG"
    AGENT_REGISTERED_IN_FUTURE    = "AGENT_REGISTERED_IN_FUTURE"

    # FRP-3 — cert_reissue_cadence.py
    CERT_REISSUE_OVERDUE          = "CERT_REISSUE_OVERDUE"
    CERT_REISSUE_TIMESTAMP_INVALID = "CERT_REISSUE_TIMESTAMP_INVALID"
    CERT_REISSUE_TIMESTAMP_IN_FUTURE = "CERT_REISSUE_TIMESTAMP_IN_FUTURE"

    # PDS-2 — score_velocity.py
    SCORE_DELTA_EXCEEDED          = "SCORE_DELTA_EXCEEDED"
    SCORE_VELOCITY_EXCEEDED       = "SCORE_VELOCITY_EXCEEDED"
    SCORE_VELOCITY_ABSURD         = "SCORE_VELOCITY_ABSURD"
    SCORE_TIME_TRAVEL             = "SCORE_TIME_TRAVEL"

    # AW-01 — cluster/pipeline.py input-commitment agreement
    INPUT_COMMITMENT_MISSING      = "INPUT_COMMITMENT_MISSING"
    INPUT_COMMITMENT_DISAGREEMENT = "INPUT_COMMITMENT_DISAGREEMENT"

    # AW-01-EXT — cluster/pipeline.py slot anchor
    SLOT_ANCHOR_MISSING           = "SLOT_ANCHOR_MISSING"

    # Quorum — cluster/aggregation.py
    QUORUM_NOT_MET                = "QUORUM_NOT_MET"

    # Cluster signing — cluster/cert_signing.py
    SIGNATURE_THRESHOLD_NOT_MET   = "SIGNATURE_THRESHOLD_NOT_MET"

    # OFAC-1 — explicit operator-side veto. This code is the ONE the
    # audit script flags hardest. If it appears on the topic, an
    # operator-of-record consciously decided NOT to score an agent. The
    # cluster MAY have a legitimate reason (e.g., a partner-side
    # `revoke_verified_consumer` cascade), but the auditor MUST verify
    # it against the recorded justification in `incidents/`.
    OPERATOR_OVERRIDE             = "OPERATOR_OVERRIDE"


class RefusalGate(str, enum.Enum):
    """Which existing defense fired the refusal."""
    NSS_3_AGENT_AGE        = "NSS-3"
    FRP_3_REISSUE_CADENCE  = "FRP-3"
    PDS_2_SCORE_VELOCITY   = "PDS-2"
    ILS_3_DRIFT_CEILING    = "ILS-3"
    AW_01_INPUT_COMMITMENT = "AW-01"
    AW_01_EXT_SLOT_ANCHOR  = "AW-01-EXT"
    QUORUM                 = "QUORUM"
    THRESHOLD_SIGNATURE    = "THRESHOLD-SIG"
    OPERATOR_OVERRIDE      = "OPERATOR-OVERRIDE"


# =============================================================================
# CertRefusal — the wire record
# =============================================================================

@dataclass(frozen=True, slots=True)
class CertRefusal:
    """
    One cert refusal — emitted onto `Topic.CERT_REFUSED` after the
    cluster considers `(agent_wallet, epoch)` and declines to issue.

    `agent_wallet`    base58 pubkey of the agent the cluster declined
                      to score.
    `epoch`           Phylanx epoch in which the refusal was decided.
    `requested_tier`  the tier the cluster would have stamped on the
                      cert if the gate had not fired (`GREEN` /
                      `YELLOW` / `RED`).
    `gate`            which defense fired the refusal. One of
                      `RefusalGate`.
    `reasons`         tuple of stable reason-code strings (from
                      `RefusalReason`). May contain >1 code when a
                      single refusal trips multiple sub-checks (e.g.
                      NSS-3 hitting both seconds AND epochs floors).
    `detected_at`     UTC timestamp of the refusal decision. Carried
                      so the indexer's audit gate can do windowed
                      rate analysis without depending on consumer
                      wall-clock.

    Frozen dataclass — once emitted, a refusal record is immutable.
    """
    agent_wallet:   str
    epoch:          int
    requested_tier: str
    gate:           RefusalGate
    reasons:        tuple[str, ...]
    detected_at:    datetime

    def __post_init__(self) -> None:
        if not self.agent_wallet or not self.agent_wallet.strip():
            raise ValueError("CertRefusal.agent_wallet must be non-empty")
        if self.epoch < 0:
            raise ValueError(
                f"CertRefusal.epoch must be >= 0, got {self.epoch}"
            )
        if not self.reasons:
            raise ValueError(
                "CertRefusal.reasons must be non-empty — a refusal "
                "with no reason codes is structurally suspect"
            )
        if self.detected_at.tzinfo is None:
            raise ValueError(
                "CertRefusal.detected_at must be tz-aware (UTC)"
            )


# =============================================================================
# Collector — what the per-epoch issuance loop holds
# =============================================================================

class CertRefusalLog:
    """
    Append-only collector for the current epoch's cert refusals.

    The oracle's issuance loop instantiates one per epoch, passes it
    into each gate-check site (as an optional parameter — gates work
    fine without it), and drains it at end-of-epoch to publish onto
    `Topic.CERT_REFUSED`.

    Thread-safety: NOT thread-safe by design — the issuance loop is
    single-threaded per epoch. If a future caller needs multi-threaded
    use, wrap in a Lock at the caller; do not introduce a Lock here
    because the per-call overhead matters for hot-path determinism.
    """

    __slots__ = ("_refusals",)

    def __init__(self) -> None:
        self._refusals: list[CertRefusal] = []

    def record(self, refusal: CertRefusal) -> None:
        """Append a refusal. O(1)."""
        if not isinstance(refusal, CertRefusal):
            raise TypeError(
                f"CertRefusalLog.record expects CertRefusal, got "
                f"{type(refusal).__name__}"
            )
        self._refusals.append(refusal)

    def drain(self) -> tuple[CertRefusal, ...]:
        """
        Return the collected refusals in record-order and clear the
        buffer. Idempotent: a second `drain()` after a previous one
        with no intervening `record()` returns `()`.
        """
        out = tuple(self._refusals)
        self._refusals = []
        return out

    def __len__(self) -> int:
        return len(self._refusals)


# =============================================================================
# Factory helpers — convert each gate's existing report dataclass into
# a `CertRefusal`. The gate modules already expose typed report
# dataclasses with `reasons` / `reason` / `is_safe` fields; these
# helpers are the one-line bridge each call site uses.
# =============================================================================

def from_agent_age_report(
    report,
    *,
    epoch:       int,
    detected_at: datetime,
) -> CertRefusal:
    """
    Convert an `oracle.agent_age_gate.AgentAgeReport` into a
    `CertRefusal`. Caller is responsible for only invoking this when
    `report.is_allowed is False`.

    Untyped on `report` so this module does NOT import the gate
    module — keeps the dependency graph one-way (gates may import
    this; this never imports gates).
    """
    if report.is_allowed:
        raise ValueError(
            "from_agent_age_report called on an allowed AgentAgeReport — "
            "only refusals should become CertRefusal records"
        )
    return CertRefusal(
        agent_wallet=report.agent_wallet,
        epoch=epoch,
        requested_tier=report.tier_requested,
        gate=RefusalGate.NSS_3_AGENT_AGE,
        reasons=tuple(report.reasons),
        detected_at=detected_at,
    )


def from_velocity_report(
    report,
    *,
    agent_wallet: str,
    epoch:        int,
    detected_at:  datetime,
) -> CertRefusal:
    """
    Convert an `oracle.score_velocity.ScoreVelocityReport` (the one
    returned by `verify_score_velocity`) into a `CertRefusal`. Caller
    is responsible for only invoking on `not report.is_safe`.
    """
    if report.is_safe:
        raise ValueError(
            "from_velocity_report called on a safe ScoreVelocityReport"
        )
    # PDS-2 report exposes either a single `reason` string or a tuple
    # `reasons`. Accept both.
    reasons = getattr(report, "reasons", None)
    if reasons is None:
        single = getattr(report, "reason", "")
        reasons = (single,) if single else ()
    return CertRefusal(
        agent_wallet=agent_wallet,
        epoch=epoch,
        requested_tier="",      # PDS-2 is tier-agnostic
        gate=RefusalGate.PDS_2_SCORE_VELOCITY,
        reasons=tuple(reasons),
        detected_at=detected_at,
    )


def operator_override(
    *,
    agent_wallet: str,
    epoch:        int,
    requested_tier: str,
    justification: str,
    detected_at:  datetime,
) -> CertRefusal:
    """
    Build a `CertRefusal` for an EXPLICIT operator-of-record veto.

    This is the ONE refusal code the audit gate flags hardest: it
    means an operator consciously refused to score an agent, and the
    auditor MUST verify the `justification` against the recorded
    incident-response entry in `incidents/`. The justification is
    folded into the `reasons` tuple as a single
    `f"OPERATOR_OVERRIDE: {justification}"` string so an auditor
    reading the topic sees the reason inline.

    Use this when (and ONLY when) the cluster is explicitly refusing
    on policy grounds — e.g., a Squads-signed temporary suspension
    after a partner-side `revoke_verified_consumer` cascade. Do NOT
    use this for a per-gate refusal (those have their own dedicated
    refusal codes above).
    """
    justification = (justification or "").strip()
    if not justification:
        raise ValueError(
            "operator_override requires a non-empty justification — a "
            "policy refusal without an auditable reason is structurally "
            "suspect and is exactly the silent-censorship case OFAC-1 "
            "is designed to surface"
        )
    return CertRefusal(
        agent_wallet=agent_wallet,
        epoch=epoch,
        requested_tier=requested_tier,
        gate=RefusalGate.OPERATOR_OVERRIDE,
        reasons=(f"{RefusalReason.OPERATOR_OVERRIDE.value}: {justification}",),
        detected_at=detected_at,
    )


__all__ = [
    "CertRefusal",
    "CertRefusalLog",
    "RefusalGate",
    "RefusalReason",
    "from_agent_age_report",
    "from_velocity_report",
    "operator_override",
]
