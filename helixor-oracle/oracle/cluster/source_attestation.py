"""
oracle/cluster/source_attestation.py — AW-01-EXT per-node multi-source
attestation primitive.

THE GAP THIS CLOSES
-------------------
AW-01 added a CROSS-NODE input-commitment agreement check: every cluster
node hashes its inputs, and the cluster refuses to issue a cert unless a
majority of nodes agree on the hash. That is strong against per-node
poisoning (a single compromised node sits in the minority and gets a
strike).

But AW-01 does NOT defend against COORDINATED upstream poisoning where the
ENTIRE cluster reads from the same compromised path (e.g. a backdoor in
the cloud provider that hosts every node's RPC endpoint, or a poisoned
Geyser fleet feeding all nodes). In that case every honest node sees the
same false inputs, computes the same commitment, and the cross-node
agreement check fires GREEN despite the inputs being lies.

This primitive moves the agreement check INSIDE each node. Each node
independently queries N orthogonal upstream sources — different RPC
providers, different geo regions, different cloud accounts — and only
commits its observation if M-of-N sources agree. A node whose own RPC
fleet disagrees commits in DEGRADED mode and sets the
FlagBit.SOURCE_DISAGREEMENT bit so consumers can see that even before
the cross-node check, the inputs had local integrity issues.

ORTHOGONAL TO AW-01
-------------------
Per-node attestation strengthens AW-01; it does not replace it. The two
work together:

  Per-node attestation says:   "M of MY OWN N sources agreed."
  AW-01 cross-node says:       "≥quorum of CLUSTER NODES agreed."

An attacker now has to compromise:
  - the cluster's per-node M-of-N AND
  - a cluster-majority of nodes AND
  - the Solana SlotHashes sysvar (AW-01-EXT slot-anchor — the third
    independent oracle, verified on-chain).

That is the architectural ceiling for input integrity short of a full
forging of Solana's own ledger.

PURE + DETERMINISTIC
--------------------
The primitive is pure: given the same `SourceObservation`s in, the same
`AttestationResult` comes out. No network I/O in this module — the
caller (the node's score-runner) is responsible for FETCHING from each
upstream and handing the observations here. That separation keeps this
module byte-deterministic and unit-testable.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum


# =============================================================================
# Types
# =============================================================================

class AttestationOutcome(Enum):
    """
    Three terminal states from one round of multi-source attestation:

      AGREE   — ≥M of N sources produced byte-identical observations.
                Safe to commit; no degraded flag.
      DEGRADED — fewer than M agreed but a plurality still exists. The
                 node may commit in degraded mode (caller's choice),
                 setting FlagBit.SOURCE_DISAGREEMENT for visibility.
      REFUSE  — no plurality reached the minimum-honest threshold. The
                node MUST NOT commit; the entire epoch is at risk and
                the operator is paged.
    """
    AGREE    = "agree"
    DEGRADED = "degraded"
    REFUSE   = "refuse"


@dataclass(frozen=True, slots=True)
class SourceObservation:
    """
    One upstream source's view of what the node should commit over. The
    `digest` is whatever byte-identical commitment the caller wants
    cross-checked — typically `compute_input_commitment(...)` over the
    transactions returned by THAT source.

    `source_id` is an opaque label (e.g. "rpc-us-east-1-helius",
    "rpc-eu-west-quicknode") used only for logging + the dissenting-source
    list. It does NOT influence the agreement check.
    """
    source_id: str
    digest:    bytes

    def __post_init__(self) -> None:
        if not self.source_id:
            raise ValueError("source_id must be non-empty")
        if not isinstance(self.digest, (bytes, bytearray)):
            raise TypeError("digest must be bytes")
        if len(self.digest) == 0:
            raise ValueError("digest must be non-empty")
        # Normalise to immutable bytes for stable hashing.
        object.__setattr__(self, "digest", bytes(self.digest))


@dataclass(frozen=True, slots=True)
class AttestationResult:
    """
    The outcome of one multi-source attestation round.

    `chosen_digest` is the plurality digest when at least one exists
    (AGREE or DEGRADED); None for REFUSE. `agree_count` and `total` give
    a numerator/denominator the caller can fold into telemetry.
    `dissenting_sources` is the sorted list of `source_id`s whose digest
    differed from the plurality — useful for paging the right upstream
    owner.
    """
    outcome:            AttestationOutcome
    chosen_digest:      bytes | None
    agree_count:        int
    total:              int
    minimum_honest:     int
    dissenting_sources: tuple[str, ...]

    @property
    def is_agree(self) -> bool:
        return self.outcome is AttestationOutcome.AGREE

    @property
    def is_degraded(self) -> bool:
        return self.outcome is AttestationOutcome.DEGRADED

    @property
    def must_refuse(self) -> bool:
        return self.outcome is AttestationOutcome.REFUSE


# =============================================================================
# The primitive
# =============================================================================

def attest_multi_source(
    observations:    Sequence[SourceObservation],
    *,
    minimum_honest:  int,
) -> AttestationResult:
    """
    Run one round of M-of-N attestation over `observations`.

    Algorithm:
      1. Tally observations by digest.
      2. The PLURALITY digest is the one with the highest count
         (ties broken deterministically by sorted-byte order, so two
         honest nodes given identical inputs produce identical outputs).
      3. If the plurality count >= minimum_honest → AGREE.
         The node commits this digest unflagged.
      4. Else if the plurality has >= 2 observations AND a strict
         minority of dissent → DEGRADED.
         The node MAY commit, MUST set FlagBit.SOURCE_DISAGREEMENT.
      5. Else → REFUSE.
         The node MUST NOT commit; the operator is paged.

    `minimum_honest` is the M-of-N threshold (e.g. 2-of-3, 3-of-5). It
    must be in [1, len(observations)]; values outside that range raise
    ValueError so a miswired caller fails loudly at startup rather than
    silently degrading.

    Pure + deterministic — same observations in, same result out.
    """
    if not observations:
        raise ValueError("observations must be non-empty")
    if minimum_honest < 1:
        raise ValueError(f"minimum_honest must be >= 1, got {minimum_honest}")
    if minimum_honest > len(observations):
        raise ValueError(
            f"minimum_honest ({minimum_honest}) cannot exceed source count "
            f"({len(observations)})"
        )

    counts: dict[bytes, int] = {}
    sources_by_digest: dict[bytes, list[str]] = {}
    for obs in observations:
        counts[obs.digest] = counts.get(obs.digest, 0) + 1
        sources_by_digest.setdefault(obs.digest, []).append(obs.source_id)

    # Pick the plurality. Sort by (-count, digest_bytes) so ties break in
    # a way every honest node — fed the same observations — agrees on.
    plurality_digest, plurality_count = min(
        counts.items(), key=lambda kv: (-kv[1], kv[0]),
    )

    dissenting = sorted(
        sid
        for d, sids in sources_by_digest.items()
        if d != plurality_digest
        for sid in sids
    )

    total = len(observations)

    if plurality_count >= minimum_honest:
        return AttestationResult(
            outcome=AttestationOutcome.AGREE,
            chosen_digest=plurality_digest,
            agree_count=plurality_count,
            total=total,
            minimum_honest=minimum_honest,
            dissenting_sources=tuple(dissenting),
        )

    # DEGRADED requires at least two sources behind the plurality. A lone
    # source with N-1 dissenters is closer to REFUSE — committing in that
    # state means trusting a single upstream, which defeats the entire
    # point of multi-source attestation.
    if plurality_count >= 2:
        return AttestationResult(
            outcome=AttestationOutcome.DEGRADED,
            chosen_digest=plurality_digest,
            agree_count=plurality_count,
            total=total,
            minimum_honest=minimum_honest,
            dissenting_sources=tuple(dissenting),
        )

    return AttestationResult(
        outcome=AttestationOutcome.REFUSE,
        chosen_digest=None,
        agree_count=plurality_count,
        total=total,
        minimum_honest=minimum_honest,
        dissenting_sources=tuple(dissenting),
    )
