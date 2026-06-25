// =============================================================================
// phylanx-sdk/src/http_client.ts — REST API-based client for Phylanx.
//
// This is the client used by the ElizaOS plugin and any off-chain consumer
// that talks to the Phylanx REST API rather than the chain directly.
// =============================================================================

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TrustScore {
  agentWallet:  string;
  score:        number;
  alert:        "GREEN" | "YELLOW" | "RED";
  source:       string;
  successRate:  number;
  anomalyFlag:  boolean;
  isFresh:      boolean;
  updatedAt:    number;
  servedAt:     number;
  cached:       boolean;
}

export interface RequireMinScoreOptions {
  allowStale?:       boolean;
  allowAnomaly?:     boolean;
  allowProvisional?: boolean;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class PhylanxError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly score?: TrustScore,
  ) {
    super(message);
    this.name = "PhylanxError";
    // Restore prototype chain for instanceof across CJS/ESM boundaries.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class AgentNotFoundError extends PhylanxError {
  constructor(agentWallet: string) {
    super("AGENT_NOT_FOUND", `agent ${agentWallet} is not registered`);
    this.name = "AgentNotFoundError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// Client-side validation: the supplied wallet is not a structurally valid
// base58 Solana pubkey, so the client rejects BEFORE any network call.
export class InvalidAgentWalletError extends PhylanxError {
  constructor(agentWallet: string) {
    super(
      "INVALID_AGENT_WALLET",
      `agent wallet ${JSON.stringify(agentWallet)} is not a valid base58 Solana pubkey`,
    );
    this.name = "InvalidAgentWalletError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// The request did not complete within the configured timeout window.
export class TimeoutError extends PhylanxError {
  constructor(timeoutMs: number) {
    super("TIMEOUT", `request timed out after ${timeoutMs}ms`);
    this.name = "TimeoutError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// `requireMinScore` guard: the agent's score is below the caller's floor.
export class ScoreTooLowError extends PhylanxError {
  constructor(score: TrustScore, minScore: number) {
    super(
      "SCORE_TOO_LOW",
      `score ${score.score} is below the required minimum ${minScore}`,
      score,
    );
    this.name = "ScoreTooLowError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// `requireMinScore` guard: the score carries an active anomaly flag, so the
// reading is refused even if the numeric value clears the floor.
export class AnomalyDetectedError extends PhylanxError {
  constructor(score: TrustScore) {
    super(
      "ANOMALY_DETECTED",
      `agent ${score.agentWallet} score carries an active anomaly flag`,
      score,
    );
    this.name = "AnomalyDetectedError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// The agent's registration has flipped inactive (e.g. operator paused it or
// the cluster deactivated the source).
export class AgentDeactivatedError extends PhylanxError {
  constructor(agentWallet: string, score?: TrustScore) {
    super("AGENT_DEACTIVATED", `agent ${agentWallet} is deactivated`, score);
    this.name = "AgentDeactivatedError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// `requireMinScore` guard: the score is stale (past its freshness window) and
// the caller did not opt into `allowStale`.
export class StaleScoreError extends PhylanxError {
  constructor(score: TrustScore) {
    super(
      "STALE_SCORE",
      `agent ${score.agentWallet} score is stale (updatedAt=${score.updatedAt})`,
      score,
    );
    this.name = "StaleScoreError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ---------------------------------------------------------------------------
// Wallet validation
// ---------------------------------------------------------------------------

const BASE58_ALPHABET = /^[1-9A-HJ-NP-Za-km-z]+$/;

/**
 * True iff `value` is a structurally valid base58 Solana pubkey
 * (32..44 chars in the bitcoin base58 alphabet — excludes 0, O, I, l).
 * This is a cheap client-side screen so a malformed wallet is rejected
 * before any network round-trip.
 */
function isValidBase58Pubkey(value: string): boolean {
  return (
    typeof value === "string" &&
    value.length >= 32 &&
    value.length <= 44 &&
    BASE58_ALPHABET.test(value)
  );
}

// ---------------------------------------------------------------------------
// HTTP Client
// ---------------------------------------------------------------------------

interface HttpClientConfig {
  apiBase:    string;
  apiKey?:    string;
  timeoutMs?: number;
  maxRetries?: number;
  cacheTtlMs?: number;
}

interface CacheEntry {
  score:     TrustScore;
  expiresAt: number;
}

export class PhylanxClient {
  private readonly apiBase:    string;
  private readonly apiKey?:    string;
  private readonly timeoutMs:  number;
  private readonly maxRetries: number;
  private readonly cacheTtlMs: number;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(config: HttpClientConfig) {
    this.apiBase    = config.apiBase.replace(/\/$/, "");
    this.apiKey     = config.apiKey;
    this.timeoutMs  = config.timeoutMs  ?? 10_000;
    this.maxRetries = config.maxRetries ?? 2;
    this.cacheTtlMs = config.cacheTtlMs ?? 30_000;
  }

  /** Fetch the current trust score for an agent wallet address. */
  async getScore(agentWallet: string): Promise<TrustScore> {
    // Client-side screen: reject a malformed wallet before any network call.
    if (!isValidBase58Pubkey(agentWallet)) {
      throw new InvalidAgentWalletError(agentWallet);
    }

    const cached = this.cache.get(agentWallet);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.score;
    }

    const raw = await this._fetchWithRetry(`/agents/${agentWallet}/health`);
    const score = this._parse(raw);

    this.cache.set(agentWallet, { score, expiresAt: Date.now() + this.cacheTtlMs });
    return score;
  }

  /**
   * Like getScore, but throws a PhylanxError if the score does not satisfy
   * the given minimum or policy flags.
   */
  async requireMinScore(
    agentWallet: string,
    minScore: number,
    opts: RequireMinScoreOptions = {},
  ): Promise<TrustScore> {
    let score: TrustScore;
    try {
      score = await this.getScore(agentWallet);
    } catch (err) {
      if (err instanceof PhylanxError) throw err;
      throw new PhylanxError(
        "NETWORK_ERROR",
        err instanceof Error ? err.message : String(err),
      );
    }

    if (score.source === "deactivated") {
      throw new AgentDeactivatedError(score.agentWallet, score);
    }
    if (score.source === "provisional" && !opts.allowProvisional) {
      // No dedicated subclass — the PROVISIONAL_SCORE code is the contract.
      throw new PhylanxError("PROVISIONAL_SCORE", "score is provisional (first 24h)", score);
    }
    if (!score.isFresh && !opts.allowStale) {
      throw new StaleScoreError(score);
    }
    if (score.anomalyFlag && !opts.allowAnomaly) {
      throw new AnomalyDetectedError(score);
    }
    if (score.score < minScore) {
      throw new ScoreTooLowError(score, minScore);
    }

    return score;
  }

  /** Evict the cached score for an agent (forces next getScore to re-fetch). */
  invalidate(agentWallet: string): void {
    this.cache.delete(agentWallet);
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private async _fetchWithRetry(path: string): Promise<unknown> {
    const url = `${this.apiBase}${path}`;
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) headers["X-API-Key"] = this.apiKey;

    let lastErr: unknown;
    let timedOut = false;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        let res: Response;
        try {
          res = await fetch(url, { headers, signal: controller.signal });
        } finally {
          clearTimeout(timer);
        }

        if (res.status === 404) {
          throw new AgentNotFoundError(path.split("/")[2] ?? "unknown");
        }
        if (!res.ok) {
          throw new PhylanxError("NETWORK_ERROR", `HTTP ${res.status} from ${url}`);
        }
        return await res.json();
      } catch (err) {
        if (err instanceof PhylanxError) throw err;
        // AbortController fires an "AbortError" when our timeout elapses.
        if (err instanceof Error && err.name === "AbortError") timedOut = true;
        lastErr = err;
        if (attempt < this.maxRetries) {
          await new Promise(r => setTimeout(r, 200 * (attempt + 1)));
        }
      }
    }
    // If every attempt aborted on the timeout, surface that specifically.
    if (timedOut) {
      throw new TimeoutError(this.timeoutMs);
    }
    throw new PhylanxError(
      "NETWORK_ERROR",
      lastErr instanceof Error ? lastErr.message : String(lastErr),
    );
  }

  private _parse(raw: unknown): TrustScore {
    const r = raw as Record<string, unknown>;
    return {
      agentWallet:  String(r["agent_wallet"] ?? ""),
      score:        Number(r["score"] ?? 0),
      alert:        (r["alert"] ?? r["alert_tier"] ?? "RED") as TrustScore["alert"],
      source:       String(r["source"] ?? "live"),
      successRate:  Number(r["success_rate"] ?? 0),
      anomalyFlag:  Boolean(r["anomaly_flag"] ?? false),
      isFresh:      (r["is_fresh"] ?? true) as boolean,
      updatedAt:    Number(r["updated_at"] ?? 0),
      servedAt:     Number(r["served_at"] ?? 0),
      cached:       Boolean(r["cached"] ?? false),
    };
  }
}
