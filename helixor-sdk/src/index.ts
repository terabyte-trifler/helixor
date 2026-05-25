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
