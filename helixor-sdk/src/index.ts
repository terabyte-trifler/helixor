// =============================================================================
// helixor-sdk — the Helixor V2 client SDK.
//
// `getScore` is the MVP-compatible entry point — same shape, new on-chain
// source. Everything else (epoch history) is additive.
// =============================================================================

// HTTP REST client (used by the ElizaOS plugin and off-chain consumers)
export {
  HelixorClient,
  HelixorError,
  AgentNotFoundError,
  type TrustScore,
  type RequireMinScoreOptions,
} from "./http_client";

// On-chain Solana client (reads certificates directly from the chain)
export {
  HelixorChainClient,
  CertificateNotFoundError,
} from "./client";
export {
  AlertTier,
  alertTierFromCode,
  type HealthScore,
  type EpochScore,
  type HelixorProgramIds,
} from "./types";
export {
  certificatePda,
  baselineStatsPda,
  issuerConfigPda,
  epochStatePda,
  epochToLeBytes,
} from "./pdas";
export {
  decodeHealthCertificate,
  decodeEpochState,
  type DecodedHealthCertificate,
  type DecodedEpochState,
} from "./decode";

// VULN-23 consumer-side guard rails — wraps any ChainReader and refuses
// stale or velocity-pumped certs before a DeFi protocol acts on them.
export {
  SafeCertReader,
  RejectReason,
  CERT_MAX_AGE_SECONDS,
  MAX_SCORE_VELOCITY,
  VELOCITY_WINDOW_EPOCHS,
  MIN_HISTORY_REQUIRED,
  type ChainReader,
  type SafeCertReaderOptions,
  type SafeScoreOk,
  type SafeScoreRejected,
  type SafeScoreResult,
} from "./safe_reader";
