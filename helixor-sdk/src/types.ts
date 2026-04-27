// =============================================================================
// @helixor/client — public types
//
// These are the types that consumers see. Stable public contract — additive
// changes only. New fields go at the bottom; never remove or rename.
// =============================================================================

/** Tri-state alert derived from the score. */
export type AlertLevel = "GREEN" | "YELLOW" | "RED";

/** Why this score was returned — lets consumers apply differentiated policy. */
export type ScoreSource = "live" | "stale" | "provisional" | "deactivated";

/** Per-component breakdown for transparency / debugging. */
export interface ScoreBreakdown {
  successRateScore: number;     // 0-500
  consistencyScore: number;     // 0-300
  stabilityScore:   number;     // 0-200
  rawScore:         number;     // 0-1000 (pre-clamp)
  guardRailApplied: boolean;
}

/** Full trust score returned by getScore(). */
export interface TrustScore {
  agentWallet: string;
  score:       number;          // 0-1000
  alert:       AlertLevel;
  source:      ScoreSource;
  successRate: number;          // 0.0-100.0 (percentage)
  anomalyFlag: boolean;
  updatedAt:   number;          // unix epoch seconds; 0 if never scored
  isFresh:     boolean;         // false if cert > 48h old

  // Optional metadata — present when source is "live" or "stale"
  breakdown?:           ScoreBreakdown;
  scoringAlgoVersion?:  number;
  weightsVersion?:      number;
  baselineHashPrefix?:  string;

  // Operational meta
  servedAt: number;
  cached:   boolean;
}

/** Short summary used by listAgents. */
export interface AgentSummary {
  agentWallet: string;
  score:       number | null;
  alert:       AlertLevel | null;
  isFresh:     boolean | null;
  updatedAt:   number | null;
}

/** Pagination response for listAgents. */
export interface AgentList {
  items:  AgentSummary[];
  total:  number;
  limit:  number;
  cursor: string | null;
}

/** Options for HelixorClient construction. */
export interface HelixorClientOptions {
  /** Base URL of the Helixor API. */
  apiBase?: string;

  /** Per-request timeout in milliseconds. Default 5000. */
  timeoutMs?: number;

  /** Max number of automatic retries on transient failures. Default 2. */
  maxRetries?: number;

  /** Optional API key sent as Authorization: Bearer <key>. */
  apiKey?: string;

  /** Optional client-side TTL cache. 0 disables. Default 30000ms. */
  cacheTtlMs?: number;

  /** Optional fetch override (useful for tests, polyfills). Default global fetch. */
  fetch?: typeof fetch;
}

/** Options accepted by requireMinScore. */
export interface RequireMinScoreOptions {
  /** If true, accept stale (>48h) scores. Default false. */
  allowStale?: boolean;

  /** If true, accept anomaly-flagged scores. Default false. */
  allowAnomaly?: boolean;

  /** If true, accept provisional (no score yet). Default false. */
  allowProvisional?: boolean;
}
