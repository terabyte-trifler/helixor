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
} from "./types";
export type { HelixorErrorCode } from "./errors";

// Default export for `import HelixorClient from "@helixor/client"`
export { HelixorClient as default } from "./client";
