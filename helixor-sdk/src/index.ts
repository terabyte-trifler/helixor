// =============================================================================
// @helixor/client — public exports
// =============================================================================

export { HelixorClient } from "./client";
export {
  HelixorError,
  AgentNotFoundError,
  InvalidAgentWalletError,
  ScoreTooLowError,
  StaleScoreError,
  AnomalyDetectedError,
  AgentDeactivatedError,
  ProvisionalScoreError,
  TimeoutError,
  NetworkError,
  ServerError,
  RateLimitedError,
} from "./errors";
export type {
  AlertLevel,
  ScoreSource,
  ScoreBreakdown,
  TrustScore,
  AgentSummary,
  AgentList,
  HelixorClientOptions,
  RequireMinScoreOptions,
  HealthScore,
  EpochScore,
  HelixorProgramIds,
} from "./types";
export { AlertTier, alertTierFromCode } from "./types";
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
export type { HelixorErrorCode } from "./errors";

// Default export for `import HelixorClient from "@helixor/client"`
export { HelixorClient as default } from "./client";
export { OnChainHelixorClient, CertificateNotFoundError } from "./onchain";
