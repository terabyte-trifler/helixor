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

from oracle.cluster.aggregation import (
    AggregatedScore,
    NodeScore,
    QuorumNotMet,
    aggregate_scores,
    quorum_for,
)
from oracle.cluster.cluster_runner import (
    ClusterAgentResult,
    ClusterEpochReport,
    ClusterEpochRunner,
    ClusterSubmitFn,
    simulate_cluster_epoch,
)
from oracle.cluster.commit_reveal import (
    NONCE_BYTES,
    canonical_scores,
    compute_commit_hash,
    new_nonce,
    verify_reveal,
)
from oracle.cluster.commit_reveal_round import (
    CommitRecord,
    CommitRejected,
    CommitRevealRound,
    RevealRecord,
    RevealRejected,
    RoundPhase,
)
from oracle.cluster.commit_reveal_runner import (
    CommitRevealAgentResult,
    CommitRevealEpochReport,
    simulate_commit_reveal_epoch,
)
from oracle.cluster.byzantine import (
    BYZANTINE_DEVIATION_THRESHOLD,
    DeviationReport,
    NodeDeviation,
    OMResult,
    analyse_deviation,
    om1_agreement,
)
from oracle.cluster.byzantine_watchdog import (
    STRIKE_THRESHOLD,
    ByzantineChallenge,
    ByzantineWatchdog,
    ChallengeFn,
    EpochByzantineFlag,
    StrikeRecord,
)
from oracle.cluster.byzantine_runner import (
    ByzantineAgentResult,
    ByzantineEpochReport,
    run_byzantine_epoch,
)
from oracle.cluster.cert_signing import (
    AggregatedSignatures,
    ClusterSignature,
    InsufficientSignatures,
    aggregate_signatures,
    build_ed25519_instructions,
    build_ed25519_ix_data,
    cert_payload_digest,
    sign_cert_digest,
)
from oracle.cluster.kafka_ingest import (
    IngestedAgentBatch,
    batch_transactions_by_agent,
    replay_from_broker,
)
from oracle.cluster.pipeline import (
    OnChainSubmitFn,
    PipelineAgentResult,
    PipelineEpochReport,
    SubmittableCertificate,
    run_full_pipeline_epoch,
)
from oracle.cluster.identity import (
    NodeIdentity,
    NodeKeypair,
    SigningUnavailable,
)
from oracle.cluster.messages import (
    AgentScore,
    CommitRequest,
    CommitResponse,
    GetScoresRequest,
    GetScoresResponse,
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
    "GetScoresRequest", "GetScoresResponse",
    "ClusterService", "ClusterTransport",
    "InProcessRegistry", "InProcessTransport", "PeerUnreachable",
    "AggregatedScore", "NodeScore", "QuorumNotMet",
    "aggregate_scores", "quorum_for",
    "ClusterEpochRunner", "ClusterEpochReport", "ClusterAgentResult",
    "ClusterSubmitFn", "simulate_cluster_epoch",
    "NONCE_BYTES", "canonical_scores", "compute_commit_hash",
    "new_nonce", "verify_reveal",
    "CommitRevealRound", "RoundPhase", "CommitRecord", "RevealRecord",
    "CommitRejected", "RevealRejected",
    "CommitRevealEpochReport", "CommitRevealAgentResult",
    "simulate_commit_reveal_epoch",
    "BYZANTINE_DEVIATION_THRESHOLD", "DeviationReport", "NodeDeviation",
    "OMResult", "analyse_deviation", "om1_agreement",
    "STRIKE_THRESHOLD", "ByzantineWatchdog", "ByzantineChallenge",
    "ChallengeFn", "EpochByzantineFlag", "StrikeRecord",
    "ByzantineEpochReport", "ByzantineAgentResult", "run_byzantine_epoch",
    "cert_payload_digest", "sign_cert_digest", "aggregate_signatures",
    "build_ed25519_ix_data", "build_ed25519_instructions",
    "ClusterSignature", "AggregatedSignatures", "InsufficientSignatures",
    "IngestedAgentBatch", "batch_transactions_by_agent", "replay_from_broker",
    "SubmittableCertificate", "PipelineAgentResult", "PipelineEpochReport",
    "OnChainSubmitFn", "run_full_pipeline_epoch",
]
