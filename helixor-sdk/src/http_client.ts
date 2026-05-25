// =============================================================================
// helixor-sdk/src/http_client.ts — REST API-based client for Helixor.
//
// This is the client used by the ElizaOS plugin and any off-chain consumer
// that talks to the Helixor REST API rather than the chain directly.
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

export class HelixorError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly score?: TrustScore,
  ) {
    super(message);
    this.name = "HelixorError";
    // Restore prototype chain for instanceof across CJS/ESM boundaries.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class AgentNotFoundError extends HelixorError {
  constructor(agentWallet: string) {
    super("AGENT_NOT_FOUND", `agent ${agentWallet} is not registered`);
    this.name = "AgentNotFoundError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
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

export class HelixorClient {
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
   * Like getScore, but throws a HelixorError if the score does not satisfy
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
      if (err instanceof HelixorError) throw err;
      throw new HelixorError(
        "NETWORK_ERROR",
        err instanceof Error ? err.message : String(err),
      );
    }

    if (score.source === "deactivated") {
      throw new HelixorError("AGENT_DEACTIVATED", "agent is deactivated", score);
    }
    if (score.source === "provisional" && !opts.allowProvisional) {
      throw new HelixorError("PROVISIONAL_SCORE", "score is provisional (first 24h)", score);
    }
    if (!score.isFresh && !opts.allowStale) {
      throw new HelixorError("STALE_SCORE", "score is stale (>48h since update)", score);
    }
    if (score.anomalyFlag && !opts.allowAnomaly) {
      throw new HelixorError("ANOMALY_DETECTED", "anomaly flag is set", score);
    }
    if (score.score < minScore) {
      throw new HelixorError(
        "SCORE_TOO_LOW",
        `score ${score.score} is below minimum ${minScore}`,
        score,
      );
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
          throw new HelixorError("NETWORK_ERROR", `HTTP ${res.status} from ${url}`);
        }
        return await res.json();
      } catch (err) {
        if (err instanceof HelixorError) throw err;
        lastErr = err;
        if (attempt < this.maxRetries) {
          await new Promise(r => setTimeout(r, 200 * (attempt + 1)));
        }
      }
    }
    throw new HelixorError(
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
