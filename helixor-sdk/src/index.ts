// =============================================================================
// helixor-sdk — the Helixor V2 client SDK.
//
// `getScore` is the MVP-compatible entry point — same shape, new on-chain
// source. Everything else (epoch history) is additive.
// =============================================================================

export {
  HelixorClient,
  CertificateNotFoundError,
} from "./client";
export {
  AlertTier,
  alertTierFromCode,
  type HealthScore,
  type TrustScore,
  type EpochScore,
  type HelixorProgramIds,
} from "./types";
export * from "./errors";
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
