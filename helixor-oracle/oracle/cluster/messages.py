"""
oracle/cluster/messages.py — the oracle-cluster protocol messages.

These are the Python-native counterparts of the messages in
`oracle/proto/cluster.proto`. They are pure frozen dataclasses — stdlib
only, no gRPC, no protobuf import — so the cluster protocol logic and its
tests never depend on the gRPC runtime being installed.

WHY NATIVE MESSAGE TYPES, NOT THE GENERATED PROTOBUF CLASSES
------------------------------------------------------------
Helixor's hard rule: zero runtime dependencies in determinism-critical
paths. A node's scoring and the cluster's consensus must be byte-identical
across machines, so they run on pure stdlib. gRPC/protobuf is TRANSPORT —
it carries these messages between nodes — but it must not reach into the
logic. So the protocol is defined twice, deliberately:
  - `cluster.proto`     — the wire schema (for the gRPC transport),
  - this module         — the native types the logic actually uses.
The gRPC transport (oracle/cluster/grpc_transport.py) translates at the
boundary; the in-process transport speaks these types directly. Either
way, the cluster logic only ever sees these dataclasses.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# =============================================================================
# VULN-22 — version-pair validation shared by CommitRequest + RevealRequest
# =============================================================================

def _validate_version_pair(
    algo: int | None, weights: int | None, *, owner: str,
) -> None:
    """
    Enforce the version fields are EITHER both unset (legacy pre-VULN-22
    caller) OR both set to u32-fitting non-negatives. A half-set pair would
    let a node ship a commit that LOOKS version-aware but binds to half a
    version tag — the round would then have no reliable way to pin or
    silently exclude. Catching it here keeps that ambiguity out of the
    protocol.
    """
    set_count = (algo is not None) + (weights is not None)
    if set_count == 1:
        raise ValueError(
            f"{owner}: scoring_algo_version and scoring_weights_version "
            f"must be set together or both omitted "
            f"(got algo={algo!r}, weights={weights!r})"
        )
    if algo is not None and not (0 <= algo <= 0xFFFFFFFF):
        raise ValueError(
            f"{owner}.scoring_algo_version out of u32 range: {algo}"
        )
    if weights is not None and not (0 <= weights <= 0xFFFFFFFF):
        raise ValueError(
            f"{owner}.scoring_weights_version out of u32 range: {weights}"
        )


# =============================================================================
# Ping
# =============================================================================

@dataclass(frozen=True, slots=True)
class PingRequest:
    """A liveness + identity probe."""
    node_id: str
    nonce:   int

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("PingRequest.node_id must be non-empty")
        if self.nonce < 0:
            raise ValueError("PingRequest.nonce must be >= 0")


@dataclass(frozen=True, slots=True)
class PingResponse:
    """The reply to a Ping — the responder's identity + epoch view."""
    node_id:       str
    nonce:         int
    current_epoch: int


# =============================================================================
# AgentScore — one agent's score within an epoch reveal
# =============================================================================

@dataclass(frozen=True, slots=True)
class AgentScore:
    """
    One agent's score, as a node would reveal it. The fields mirror the
    on-chain certificate payload so a revealed score maps straight onto a
    `submit_score` / `issue_certificate` call.

    Day 37 — commit-reveal payload v2:
      * `failure_mode_bitmask` (u64) — the diagnosis kernel's label
        bitmask for this agent. Folded into the commit hash, so a node
        cannot change which labels it asserted between commit and reveal.
        Aggregated by per-bit majority vote (`aggregation.py`).
      * `diagnosis_payload_hash` (32 raw bytes or empty) — the SHA-256 of
        the kernel's canonical JSON for this agent. The aggregator
        requires an EXACT-MATCH honest majority on this hash — a node
        whose kernel diverged from the majority is excluded from the cert
        signing set with a hard deviation (no flap window).

    Both fields default to "no diagnosis" (0 / b"") so pre-Day-37 callers
    and the score-only single-node path keep the same wire shape.
    """
    agent_wallet:  str
    score:         int
    alert_tier:    int        # 0 GREEN, 1 YELLOW, 2 RED
    flags:         int
    immediate_red: bool
    confidence:    int
    # Day 37 — diagnosis label bitmask (u64). 0 = no kernel run / no labels.
    failure_mode_bitmask: int = 0
    # Day 37 — sha256 of the kernel's canonical JSON, raw 32 bytes. Empty
    # bytes when no kernel ran (the score-only legacy path). The
    # canonical wire form pads empty to 32 zero bytes so every agent
    # record is fixed-width.
    diagnosis_payload_hash: bytes = b""

    def __post_init__(self) -> None:
        if not (0 <= self.score <= 1000):
            raise ValueError(f"score out of range: {self.score}")
        if self.alert_tier not in (0, 1, 2):
            raise ValueError(f"alert_tier must be 0/1/2, got {self.alert_tier}")
        if not (0 <= self.confidence <= 1000):
            raise ValueError(f"confidence out of range: {self.confidence}")
        if not (0 <= self.flags <= 0xFFFFFFFF):
            raise ValueError(f"flags must be u32, got {self.flags}")
        if not (0 <= self.failure_mode_bitmask <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError(
                f"failure_mode_bitmask must be u64, "
                f"got {self.failure_mode_bitmask}"
            )
        if self.diagnosis_payload_hash and len(self.diagnosis_payload_hash) != 32:
            raise ValueError(
                f"diagnosis_payload_hash must be empty or 32 bytes, "
                f"got {len(self.diagnosis_payload_hash)}"
            )


# =============================================================================
# Commit — phase 1 of commit-reveal
# =============================================================================

@dataclass(frozen=True, slots=True)
class CommitRequest:
    """
    A node's commitment: the hash of its epoch scores (scores hidden).

    VULN-22: `scoring_algo_version` and `scoring_weights_version` are the
    scoring algorithm + weight versions the committing node ran. They are
    optional (default None for back-compat with the legacy round suite),
    but the cluster runner sets them on every honest commit. The
    `CommitRevealRound` pins to the first version it sees AND folds it
    into the commit hash — so a mid-round version switch by a revealer is
    caught by hash mismatch, and a mismatched commit is silently EXCLUDED
    (not flagged Byzantine) until the node upgrades.
    """
    node_id:     str
    epoch:       int
    commit_hash: bytes
    # VULN-22: must EITHER both be None (legacy / pre-VULN-22 caller) OR
    # both be set (a version-aware node). The round rejects half-set tuples.
    scoring_algo_version:    int | None = None
    scoring_weights_version: int | None = None

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("CommitRequest.node_id must be non-empty")
        if self.epoch < 1:
            raise ValueError("CommitRequest.epoch must be >= 1")
        if len(self.commit_hash) != 32:
            raise ValueError(
                f"commit_hash must be 32 bytes (SHA-256), "
                f"got {len(self.commit_hash)}"
            )
        _validate_version_pair(
            self.scoring_algo_version, self.scoring_weights_version,
            owner="CommitRequest",
        )


@dataclass(frozen=True, slots=True)
class CommitResponse:
    """A peer's acknowledgement of a commit."""
    accepted: bool
    reason:   str = ""


# =============================================================================
# Reveal — phase 2 of commit-reveal
# =============================================================================

@dataclass(frozen=True, slots=True)
class RevealRequest:
    """
    A node revealing its actual epoch scores + the commit salt.

    VULN-22: carries the same (scoring_algo_version, scoring_weights_version)
    pair the node committed under. The round folds the version into the
    recomputed hash AND cross-checks the carried version against the
    round's pinned version — a revealer that mutates either fails
    verification, not silently shifts the median.

    AW-01: `input_commitments` carries the per-agent input-provenance
    commitments the node bound into its commit hash — one (agent_wallet,
    32-byte SHA-256 commitment) pair per agent the node scored. Peers
    verify the reveal by folding these exact bytes into the recomputed
    hash; the aggregator additionally requires a cross-node MAJORITY to
    agree on each commitment before issuing a cert. Optional for
    back-compat with pre-AW-01 callers and tests; honest cluster nodes
    set it on every reveal.
    """
    node_id: str
    epoch:   int
    scores:  tuple[AgentScore, ...]
    salt:    bytes
    # VULN-22: same all-or-nothing semantics as CommitRequest.
    scoring_algo_version:    int | None = None
    scoring_weights_version: int | None = None
    # AW-01: per-agent input-provenance commitments. None preserves the
    # pre-AW-01 wire format; honest nodes populate it.
    input_commitments: tuple[tuple[str, bytes], ...] | None = None

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("RevealRequest.node_id must be non-empty")
        if self.epoch < 1:
            raise ValueError("RevealRequest.epoch must be >= 1")
        if not isinstance(self.scores, tuple):
            object.__setattr__(self, "scores", tuple(self.scores))
        _validate_version_pair(
            self.scoring_algo_version, self.scoring_weights_version,
            owner="RevealRequest",
        )
        if self.input_commitments is not None:
            if not isinstance(self.input_commitments, tuple):
                object.__setattr__(
                    self, "input_commitments",
                    tuple(self.input_commitments),
                )
            for wallet, commitment in self.input_commitments:
                if not wallet:
                    raise ValueError(
                        "RevealRequest.input_commitments: empty wallet"
                    )
                if len(commitment) != 32:
                    raise ValueError(
                        f"RevealRequest.input_commitments[{wallet!r}]: "
                        f"commitment must be 32 bytes, got {len(commitment)}"
                    )


@dataclass(frozen=True, slots=True)
class RevealResponse:
    """A peer's verification of a reveal against the earlier commit."""
    verified: bool
    reason:   str = ""


# =============================================================================
# GetScores — Day-24 score exchange for median aggregation
# =============================================================================

@dataclass(frozen=True, slots=True)
class GetScoresRequest:
    """
    A request for a peer's epoch scores, so the caller can aggregate the
    cluster median. Unlike commit-reveal (where scores are hidden until all
    nodes have committed), Day-24 aggregation exchanges scores directly —
    commit-reveal hardening is a later Phase-4 day.
    """
    node_id: str
    epoch:   int

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("GetScoresRequest.node_id must be non-empty")
        if self.epoch < 1:
            raise ValueError("GetScoresRequest.epoch must be >= 1")


@dataclass(frozen=True, slots=True)
class GetScoresResponse:
    """
    A peer's epoch scores. `available` is False if the peer has not yet
    scored this epoch — the caller treats that exactly like an offline
    peer (the node simply does not contribute to the median).
    """
    node_id:   str
    epoch:     int
    available: bool
    scores:    tuple[AgentScore, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.scores, tuple):
            object.__setattr__(self, "scores", tuple(self.scores))
