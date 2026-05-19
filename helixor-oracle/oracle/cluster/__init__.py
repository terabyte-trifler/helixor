"""
oracle/cluster — the Helixor oracle-cluster layer.

Phase 4 turns the single trusted oracle into a 3-5 node Byzantine-fault-
tolerant cluster. This package holds the cluster primitives:

  identity        — NodeKeypair / NodeIdentity (Ed25519, Solana's curve)
  messages        — the pure-stdlib protocol message types
  transport       — the ClusterTransport interface + InProcessTransport
  grpc_transport  — the real gRPC transport (the edge; imports grpcio
                    lazily so the rest of the package needs no gRPC)

The cluster LOGIC depends only on `messages` and `transport` — so the
whole protocol is testable with zero gRPC dependency. `grpc_transport` is
the only place gRPC enters.
"""

from __future__ import annotations

from oracle.cluster.identity import (
    NodeIdentity,
    NodeKeypair,
    SigningUnavailable,
)
from oracle.cluster.messages import (
    AgentScore,
    CommitRequest,
    CommitResponse,
    PingRequest,
    PingResponse,
    RevealRequest,
    RevealResponse,
)
from oracle.cluster.transport import (
    ClusterService,
    ClusterTransport,
    InProcessRegistry,
    InProcessTransport,
    PeerUnreachable,
)

__all__ = [
    "NodeIdentity", "NodeKeypair", "SigningUnavailable",
    "PingRequest", "PingResponse",
    "CommitRequest", "CommitResponse",
    "RevealRequest", "RevealResponse", "AgentScore",
    "ClusterService", "ClusterTransport",
    "InProcessRegistry", "InProcessTransport", "PeerUnreachable",
]
