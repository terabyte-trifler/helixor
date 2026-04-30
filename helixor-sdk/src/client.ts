// =============================================================================
// @helixor/client — HelixorClient
//
// Two methods that 99% of integrations will use:
//   getScore(agentWallet)              — fetch current trust score
//   requireMinScore(agent, min, opts)  — throw if policy fails
//
// Production features:
//   - Configurable timeout (default 5s) — DeFi transactions can't hang
//   - Automatic retry with exponential backoff on 5xx / network errors
//   - Client-side TTL cache (default 30s) — multiple checks in one tx
//     do one HTTP call
//   - Strict typed errors with stable codes consumers can switch on
//   - Optional API key (Authorization: Bearer)
//   - AbortController-based cancellation
// =============================================================================

import { ClientCache } from "./cache";
import {
  AgentDeactivatedError,
  AgentNotFoundError,
  AnomalyDetectedError,
  HelixorError,
  InvalidAgentWalletError,
  NetworkError,
  ProvisionalScoreError,
  RateLimitedError,
  ScoreTooLowError,
  ServerError,
  StaleScoreError,
  TimeoutError,
} from "./errors";
import type {
  AgentList,
  HelixorClientOptions,
  RequireMinScoreOptions,
  TrustScore,
} from "./types";

const DEFAULT_API_BASE   = "https://api.helixor.xyz";
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_RETRIES = 2;
const DEFAULT_CACHE_TTL_MS = 30_000;

// Validate base58 pubkey shape. Same regex as the server.
const PUBKEY_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

export class HelixorClient {
  private readonly apiBase:   string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly apiKey?:   string;
  private readonly fetcher:   typeof fetch;
  private readonly cache:     ClientCache<TrustScore>;
  private readonly inflight:  Map<string, Promise<TrustScore>>;

  constructor(options: HelixorClientOptions = {}) {
    this.apiBase    = (options.apiBase ?? DEFAULT_API_BASE).replace(/\/+$/, "");
    this.timeoutMs  = options.timeoutMs   ?? DEFAULT_TIMEOUT_MS;
    this.maxRetries = options.maxRetries  ?? DEFAULT_MAX_RETRIES;
    this.apiKey     = options.apiKey;
    this.cache      = new ClientCache<TrustScore>(options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS);
    this.inflight   = new Map<string, Promise<TrustScore>>();

    // Use injected fetch if provided (tests/Node polyfills); otherwise global.
    const f = options.fetch ?? globalThis.fetch;
    if (!f) {
      throw new Error(
        "Helixor: no fetch available. On Node < 18, install undici and pass it via options.fetch.",
      );
    }
    this.fetcher = f.bind(globalThis);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Public API
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Get the current trust score for an agent.
   * @throws InvalidAgentWalletError if agentWallet isn't valid base58
   * @throws AgentNotFoundError      if agent is not registered (HTTP 404)
   * @throws RateLimitedError        if rate limited (HTTP 429)
   * @throws TimeoutError            if request exceeds timeoutMs
   * @throws NetworkError            on network failure
   * @throws ServerError             on persistent 5xx after retries
   */
  async getScore(agentWallet: string): Promise<TrustScore> {
    if (!PUBKEY_RE.test(agentWallet)) {
      throw new InvalidAgentWalletError(agentWallet);
    }

    const cached = this.cache.get(agentWallet);
    if (cached) return cached;

    const existing = this.inflight.get(agentWallet);
    if (existing) return existing;

    const request = this.fetchScoreWithRetry(agentWallet)
      .then((score) => {
        this.cache.set(agentWallet, score);
        return score;
      })
      .finally(() => {
        this.inflight.delete(agentWallet);
      });

    this.inflight.set(agentWallet, request);
    return request;
  }

  /**
   * Enforce a minimum score policy. Designed to be called inside DeFi
   * transaction builders and elizaOS action handlers.
   *
   * Default policy (strictest):
   *   - Score >= minimumScore
   *   - is_fresh = true
   *   - anomaly_flag = false
   *   - source != "deactivated"
   *   - source != "provisional"
   *
   * Each can be relaxed via opts.
   *
   * @throws ScoreTooLowError | StaleScoreError | AnomalyDetectedError |
   *         AgentDeactivatedError | ProvisionalScoreError
   */
  async requireMinScore(
    agentWallet: string,
    minimumScore: number,
    opts: RequireMinScoreOptions = {},
  ): Promise<TrustScore> {
    const score = await this.getScore(agentWallet);

    // Hardest violations first — never overridable
    if (score.source === "deactivated") {
      throw new AgentDeactivatedError(score);
    }

    if (score.source === "provisional" && !opts.allowProvisional) {
      throw new ProvisionalScoreError(score);
    }

    if (!score.isFresh && !opts.allowStale) {
      throw new StaleScoreError(score);
    }

    if (score.anomalyFlag && !opts.allowAnomaly) {
      throw new AnomalyDetectedError(score);
    }

    if (score.score < minimumScore) {
      throw new ScoreTooLowError(score, minimumScore);
    }

    return score;
  }

  /** List active agents (paginated). */
  async listAgents(limit = 50, offset = 0): Promise<AgentList> {
    const url = `${this.apiBase}/agents?limit=${limit}&offset=${offset}`;
    const response = await this.requestJson(url);
    return {
      items:  (response.items ?? []).map((it: any) => ({
        agentWallet: it.agent_wallet,
        score:       it.score,
        alert:       it.alert,
        isFresh:     it.is_fresh,
        updatedAt:   it.updated_at,
      })),
      total:  response.total ?? 0,
      limit:  response.limit ?? limit,
      cursor: response.cursor ?? null,
    };
  }

  /** Invalidate the client-side cache for one agent. */
  invalidate(agentWallet: string): void {
    this.cache.invalidate(agentWallet);
    this.inflight.delete(agentWallet);
  }

  /** Clear the client-side cache entirely. */
  clearCache(): void {
    this.cache.clear();
    this.inflight.clear();
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Internals
  // ───────────────────────────────────────────────────────────────────────────

  private async fetchScoreWithRetry(agentWallet: string): Promise<TrustScore> {
    const url = `${this.apiBase}/score/${agentWallet}`;

    let lastError: HelixorError | null = null;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        const data = await this.requestJson(url);
        return this.normalizeScore(data);
      } catch (err) {
        if (err instanceof HelixorError) {
          // Don't retry permanent errors
          const permanent: string[] = [
            "AGENT_NOT_FOUND",
            "INVALID_AGENT_WALLET",
            "RATE_LIMITED",
          ];
          if (permanent.includes(err.code)) {
            throw err;
          }
          lastError = err;
        } else {
          lastError = new NetworkError(String(err));
        }

        // Exponential backoff: 100ms, 300ms, 900ms
        if (attempt < this.maxRetries) {
          const wait = 100 * Math.pow(3, attempt);
          await new Promise(resolve => setTimeout(resolve, wait));
        }
      }
    }

    throw lastError ?? new NetworkError("Unknown error after retries");
  }

  private async requestJson(url: string): Promise<any> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);

    const headers: Record<string, string> = {
      "Accept":     "application/json",
      "User-Agent": "@helixor/client/0.8.0",
    };
    if (this.apiKey) {
      headers["Authorization"] = `Bearer ${this.apiKey}`;
    }

    let response: Response;
    try {
      response = await this.fetcher(url, {
        method:  "GET",
        headers,
        signal:  ctrl.signal,
      });
    } catch (err: any) {
      clearTimeout(timer);
      if (err?.name === "AbortError") {
        throw new TimeoutError(this.timeoutMs);
      }
      throw new NetworkError(String(err?.message ?? err));
    } finally {
      clearTimeout(timer);
    }

    const requestId = response.headers.get("x-request-id") ?? undefined;

    if (response.status === 404) {
      const body = await this.safeJson(response);
      throw new AgentNotFoundError(body?.agent_wallet ?? "unknown", requestId);
    }
    if (response.status === 429) {
      const retryAfter = parseInt(response.headers.get("retry-after") ?? "60", 10);
      throw new RateLimitedError(retryAfter);
    }
    if (response.status >= 500) {
      const body = await this.safeJson(response);
      throw new ServerError(response.status, body?.error ?? "Server error", requestId);
    }
    if (!response.ok) {
      const body = await this.safeJson(response);
      throw new HelixorError(
        "INVALID_RESPONSE",
        `Unexpected status ${response.status}: ${body?.error ?? response.statusText}`,
        undefined,
        requestId,
      );
    }

    return await this.safeJson(response);
  }

  private async safeJson(response: Response): Promise<any> {
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  /** Convert the snake_case JSON payload into our camelCase TrustScore. */
  private normalizeScore(data: any): TrustScore {
    if (!data || typeof data !== "object") {
      throw new HelixorError("INVALID_RESPONSE", "Empty response body");
    }
    return {
      agentWallet: data.agent_wallet,
      score:       data.score,
      alert:       data.alert,
      source:      data.source ?? "live",
      successRate: data.success_rate,
      anomalyFlag: data.anomaly_flag,
      updatedAt:   data.updated_at,
      isFresh:     data.is_fresh,
      breakdown:   data.breakdown ? {
        successRateScore: data.breakdown.success_rate_score,
        consistencyScore: data.breakdown.consistency_score,
        stabilityScore:   data.breakdown.stability_score,
        rawScore:         data.breakdown.raw_score,
        guardRailApplied: data.breakdown.guard_rail_applied,
      } : undefined,
      scoringAlgoVersion: data.scoring_algo_version ?? undefined,
      weightsVersion:     data.weights_version ?? undefined,
      baselineHashPrefix: data.baseline_hash_prefix ?? undefined,
      servedAt: data.served_at,
      cached:   data.cached,
    };
  }
}
