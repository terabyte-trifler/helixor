"""
phylanx-indexer — the Geyser indexer.

Streams every transaction touching a registered agent wallet off a
Geyser-enabled RPC (Yellowstone gRPC) and writes it to TimescaleDB within
~500ms of on-chain confirmation. The Helius webhook receiver runs alongside
as a fallback / reconciliation source.

Public API:
    GeyserIndexer, RunReport, INGEST_SLA_MS      the runner
    IngestionWriter                              decode + persist
    WalletFilter, StreamSource, ListStreamSource the stream + filter
    decode_transaction, DecodeError              the pure decoder
    WebhookReceiver, decode_webhook_payload      the webhook fallback
    reconcile_agent, reconcile_all,              the reconciler
        ReconciliationResult, DivergenceSeverity
    YellowstoneStreamSource, YellowstoneConfig   the live gRPC edge
    GeyserTransactionUpdate, GeyserAccountChange,
        IngestedTransaction, IngestionSource     the types

    VULN-11 — stream authentication & defence in depth:
        canonical_update_bytes, commitment,
        SignedGeyserUpdate, sign_update,
        TrustedGeyserSource, TrustedGeyserSourceSet,
        verify_signed_update, VerifyingStreamSource,
        GeyserAuthError, UntrustedSource         envelope auth (mit. #1)
        CrossVerificationFailed,
        RpcSignatureStatus, RpcSignatureVerifier,
        SamplingCrossVerifier, cross_check       RPC cross-check (mit. #2)
        ConflictReport, ConsensusStream          multi-endpoint (mit. #3)
        PluginPin, PluginPinManifest,
        TrustedReleaseSigner, TrustedReleaseSignerSet,
        compute_binary_sha256, verify_plugin_binary,
        manifest_from_json, manifest_to_json,
        PluginPinError, UntrustedReleaseSigner   plugin pinning (mit. #4)
"""

from __future__ import annotations

from indexer.auth import (
    GeyserAuthError,
    SignedGeyserUpdate,
    TrustedGeyserSource,
    TrustedGeyserSourceSet,
    UntrustedSource,
    VerifyingStreamSource,
    canonical_update_bytes,
    commitment,
    sign_update,
    verify_signed_update,
)
from indexer.consensus import ConflictReport, ConsensusStream
from indexer.cross_verify import (
    CrossVerificationFailed,
    RpcSignatureStatus,
    RpcSignatureVerifier,
    SamplingCrossVerifier,
    cross_check,
)
from indexer.decoder import DecodeError, decode_transaction
from indexer.plugin_pin import (
    PluginPin,
    PluginPinError,
    PluginPinManifest,
    TrustedReleaseSigner,
    TrustedReleaseSignerSet,
    UntrustedReleaseSigner,
    compute_binary_sha256,
    manifest_from_json,
    manifest_to_json,
    verify_plugin_binary,
)
from indexer.production_config import (
    CLUSTER_ENV,
    ENDPOINTS_ENV,
    MAINNET_CLUSTERS,
    MAINNET_MIN_ENDPOINTS,
    MIN_CONSENSUS_THRESHOLD,
    GeyserConfigError,
    ProductionGeyserConfig,
    SinglePointGeyserError,
    build_production_geyser_config,
)
from indexer.reconciler import (
    DivergenceSeverity,
    ReconciliationReport,
    ReconciliationResult,
    reconcile_agent,
    reconcile_all,
)
from indexer.runner import INGEST_SLA_MS, GeyserIndexer, RunReport
from indexer.stream import ListStreamSource, StreamSource, WalletFilter
from indexer.types import (
    GeyserAccountChange,
    GeyserTransactionUpdate,
    IngestedTransaction,
    IngestionSource,
)
from indexer.webhook_fallback import (
    WebhookDecodeError,
    WebhookReceiver,
    decode_webhook_payload,
)
from indexer.writer import IngestionWriter
from indexer.yellowstone import (
    YellowstoneConfig,
    YellowstoneStreamSource,
    map_subscribe_update,
)

__all__ = [
    "GeyserIndexer", "RunReport", "INGEST_SLA_MS",
    "IngestionWriter",
    "WalletFilter", "StreamSource", "ListStreamSource",
    "decode_transaction", "DecodeError",
    "WebhookReceiver", "decode_webhook_payload", "WebhookDecodeError",
    "reconcile_agent", "reconcile_all",
    "ReconciliationResult", "ReconciliationReport", "DivergenceSeverity",
    "YellowstoneStreamSource", "YellowstoneConfig", "map_subscribe_update",
    "GeyserTransactionUpdate", "GeyserAccountChange",
    "IngestedTransaction", "IngestionSource",
    # VULN-11
    "canonical_update_bytes", "commitment",
    "SignedGeyserUpdate", "sign_update",
    "TrustedGeyserSource", "TrustedGeyserSourceSet",
    "verify_signed_update", "VerifyingStreamSource",
    "GeyserAuthError", "UntrustedSource",
    "CrossVerificationFailed",
    "RpcSignatureStatus", "RpcSignatureVerifier",
    "SamplingCrossVerifier", "cross_check",
    "ConflictReport", "ConsensusStream",
    "PluginPin", "PluginPinManifest",
    "TrustedReleaseSigner", "TrustedReleaseSignerSet",
    "compute_binary_sha256", "verify_plugin_binary",
    "manifest_from_json", "manifest_to_json",
    "PluginPinError", "UntrustedReleaseSigner",
    # SPOF-#8 — multi-endpoint production default
    "CLUSTER_ENV", "ENDPOINTS_ENV",
    "MAINNET_CLUSTERS", "MAINNET_MIN_ENDPOINTS", "MIN_CONSENSUS_THRESHOLD",
    "GeyserConfigError", "SinglePointGeyserError",
    "ProductionGeyserConfig", "build_production_geyser_config",
]
