// =============================================================================
// @helixor/client — errors
//
// Each error carries a stable code so consumers can switch on it. Error
// classes are subclasses of HelixorError so a catch (HelixorError) catches
// everything from the SDK.
// =============================================================================

import type { TrustScore } from "./types";

/** Stable error codes — additive only. */
export type HelixorErrorCode =
  | "AGENT_NOT_FOUND"
  | "INVALID_AGENT_WALLET"
  | "SCORE_TOO_LOW"
  | "STALE_SCORE"
  | "ANOMALY_DETECTED"
  | "AGENT_DEACTIVATED"
  | "PROVISIONAL_SCORE"
  | "RATE_LIMITED"
  | "TIMEOUT"
  | "NETWORK_ERROR"
  | "SERVER_ERROR"
  | "INVALID_RESPONSE";

/** Base SDK error. Always thrown — consumers can catch this for everything. */
export class HelixorError extends Error {
  public readonly code:      HelixorErrorCode;
  public readonly score?:    TrustScore;
  public readonly requestId?: string;

  constructor(
    code:      HelixorErrorCode,
    message:   string,
    score?:    TrustScore,
    requestId?: string,
  ) {
    super(`Helixor[${code}]: ${message}`);
    this.name = "HelixorError";
    this.code = code;
    this.score = score;
    this.requestId = requestId;
    Object.setPrototypeOf(this, HelixorError.prototype);
  }
}

/** Agent not registered with Helixor. */
export class AgentNotFoundError extends HelixorError {
  constructor(agentWallet: string, requestId?: string) {
    super("AGENT_NOT_FOUND", `Agent ${agentWallet} is not registered.`, undefined, requestId);
    this.name = "AgentNotFoundError";
    Object.setPrototypeOf(this, AgentNotFoundError.prototype);
  }
}

/** Bad input — invalid base58 pubkey, etc. */
export class InvalidAgentWalletError extends HelixorError {
  constructor(agentWallet: string) {
    super("INVALID_AGENT_WALLET", `'${agentWallet}' is not a valid Solana pubkey.`);
    this.name = "InvalidAgentWalletError";
    Object.setPrototypeOf(this, InvalidAgentWalletError.prototype);
  }
}

/** Policy errors thrown by requireMinScore. Carry the actual TrustScore. */
export class ScoreTooLowError extends HelixorError {
  constructor(score: TrustScore, minimum: number) {
    super(
      "SCORE_TOO_LOW",
      `Score ${score.score} is below required minimum ${minimum}.`,
      score,
    );
    this.name = "ScoreTooLowError";
    Object.setPrototypeOf(this, ScoreTooLowError.prototype);
  }
}

export class StaleScoreError extends HelixorError {
  constructor(score: TrustScore) {
    super(
      "STALE_SCORE",
      `Score is stale (last updated ${score.updatedAt}, source=${score.source}).`,
      score,
    );
    this.name = "StaleScoreError";
    Object.setPrototypeOf(this, StaleScoreError.prototype);
  }
}

export class AnomalyDetectedError extends HelixorError {
  constructor(score: TrustScore) {
    super(
      "ANOMALY_DETECTED",
      `Agent has anomaly_flag=true (score=${score.score}).`,
      score,
    );
    this.name = "AnomalyDetectedError";
    Object.setPrototypeOf(this, AnomalyDetectedError.prototype);
  }
}

export class AgentDeactivatedError extends HelixorError {
  constructor(score: TrustScore) {
    super("AGENT_DEACTIVATED", `Agent has been deactivated by its owner.`, score);
    this.name = "AgentDeactivatedError";
    Object.setPrototypeOf(this, AgentDeactivatedError.prototype);
  }
}

export class ProvisionalScoreError extends HelixorError {
  constructor(score: TrustScore) {
    super("PROVISIONAL_SCORE", `Agent has no real score yet (provisional).`, score);
    this.name = "ProvisionalScoreError";
    Object.setPrototypeOf(this, ProvisionalScoreError.prototype);
  }
}

/** Transport errors. */
export class TimeoutError extends HelixorError {
  constructor(timeoutMs: number) {
    super("TIMEOUT", `Request timed out after ${timeoutMs}ms.`);
    this.name = "TimeoutError";
    Object.setPrototypeOf(this, TimeoutError.prototype);
  }
}

export class NetworkError extends HelixorError {
  constructor(message: string) {
    super("NETWORK_ERROR", message);
    this.name = "NetworkError";
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}

export class ServerError extends HelixorError {
  constructor(statusCode: number, message: string, requestId?: string) {
    super("SERVER_ERROR", `Server returned ${statusCode}: ${message}`, undefined, requestId);
    this.name = "ServerError";
    Object.setPrototypeOf(this, ServerError.prototype);
  }
}

export class RateLimitedError extends HelixorError {
  constructor(retryAfterSeconds?: number) {
    super(
      "RATE_LIMITED",
      `Rate limited${retryAfterSeconds ? `, retry after ${retryAfterSeconds}s` : ""}.`,
    );
    this.name = "RateLimitedError";
    Object.setPrototypeOf(this, RateLimitedError.prototype);
  }
}
