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
    """
    agent_wallet:  str
    score:         int
    alert_tier:    int        # 0 GREEN, 1 YELLOW, 2 RED
    flags:         int
    immediate_red: bool
    confidence:    int

    def __post_init__(self) -> None:
        if not (0 <= self.score <= 1000):
            raise ValueError(f"score out of range: {self.score}")
        if self.alert_tier not in (0, 1, 2):
            raise ValueError(f"alert_tier must be 0/1/2, got {self.alert_tier}")
        if not (0 <= self.confidence <= 1000):
            raise ValueError(f"confidence out of range: {self.confidence}")
        if not (0 <= self.flags <= 0xFFFFFFFF):
            raise ValueError(f"flags must be u32, got {self.flags}")


# =============================================================================
# Commit — phase 1 of commit-reveal
# =============================================================================

@dataclass(frozen=True, slots=True)
class CommitRequest:
    """A node's commitment: the hash of its epoch scores (scores hidden)."""
    node_id:     str
    epoch:       int
    commit_hash: bytes

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
    """A node revealing its actual epoch scores + the commit salt."""
    node_id: str
    epoch:   int
    scores:  tuple[AgentScore, ...]
    salt:    bytes

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("RevealRequest.node_id must be non-empty")
        if self.epoch < 1:
            raise ValueError("RevealRequest.epoch must be >= 1")
        if not isinstance(self.scores, tuple):
            object.__setattr__(self, "scores", tuple(self.scores))


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
