// =============================================================================
// src/score_cache.ts — VULN-12 mitigation core: last-known-good cache + the
// pure policy function used to evaluate that cache when the API is down.
//
// THE AUDIT FINDING
// -----------------
// VULN-12 (HIGH): the trust_gate evaluator's behaviour on score-fetch failure
// determined the blast radius of an API outage. An attacker who DDoSed the
// Helixor API would force every trust_gate to either:
//
//   (a) FAIL OPEN — allow the action ungated. Their RED-scored agent walks
//       into every DeFi integration during the blackout window and borrows
//       the max. By the time the API recovers and the RED score is visible
//       again, the funds are already gone.
//
//   (b) FAIL CLOSED — block the action. Safe, but a DDoS becomes a kill
//       switch for the whole agent fleet, which is its own DoS.
//
// The audit-mandated fix is a third path: FAIL TO LAST-KNOWN-GOOD. If we
// have a recently fetched score in local cache, evaluate the policy against
// THAT score (a freshly-pulled RED score is RED for at least the next few
// minutes; a freshly-pulled GREEN score is similarly stable). Only when the
// cache is missing or older than the TTL do we fail closed.
//
// THIS FILE
// ---------
// Two primitives:
//
//   1. `applyPolicy(score, opts)` — a PURE synchronous mirror of
//      `HelixorClient.requireMinScore`'s policy. Same precedence
//      (deactivated -> provisional -> stale -> anomaly -> score). Used by
//      the trust_gate to evaluate a CACHED score without going to the
//      network. The SDK is the canonical source of truth; this is a
//      tight mirror — if the SDK adds a check, mirror it here.
//
//   2. `ScoreCache(ttlMs)` — a single-slot last-known-good cache. `put` on
//      every successful fetch; `getIfFresh(now)` returns the cached entry
//      only when its age is < TTL. The trust_gate's fail-closed branch
//      consults this before deciding.
//
// Both are sync, dependency-free, and exhaustively unit-testable.
// =============================================================================

import type { TrustScore } from "@helixor/client";


// =============================================================================
// Policy evaluation — the pure mirror of requireMinScore
// =============================================================================

export type PolicyCode =
  | "AGENT_DEACTIVATED"
  | "PROVISIONAL_SCORE"
  | "STALE_SCORE"
  | "ANOMALY_DETECTED"
  | "SCORE_TOO_LOW";

export interface PolicyOptions {
  minScore:          number;
  allowStale:        boolean;
  allowAnomaly:      boolean;
  allowProvisional:  boolean;
}

export interface PolicyResult {
  allowed: boolean;
  code?:   PolicyCode;
}

/**
 * Apply the trust-gate policy to a (cached or live) score.
 *
 * Mirrors `HelixorClient.requireMinScore` (helixor-sdk/src/http_client.ts).
 * KEEP THIS IN LOCK-STEP: the SDK is the authority. The local mirror exists
 * so that the trust_gate can evaluate a cached score without going to the
 * network during an API blackout (the VULN-12 fail-closed-with-cache path).
 *
 * Precedence is identical to the SDK:
 *   1. deactivated  → AGENT_DEACTIVATED  (unbypassable)
 *   2. provisional & !allowProvisional → PROVISIONAL_SCORE
 *   3. !isFresh    & !allowStale       → STALE_SCORE
 *   4. anomalyFlag & !allowAnomaly     → ANOMALY_DETECTED
 *   5. score < minScore                → SCORE_TOO_LOW
 *   6. otherwise                       → allowed
 */
export function applyPolicy(
  score: TrustScore,
  opts:  PolicyOptions,
): PolicyResult {
  if (score.source === "deactivated") {
    return { allowed: false, code: "AGENT_DEACTIVATED" };
  }
  if (score.source === "provisional" && !opts.allowProvisional) {
    return { allowed: false, code: "PROVISIONAL_SCORE" };
  }
  if (!score.isFresh && !opts.allowStale) {
    return { allowed: false, code: "STALE_SCORE" };
  }
  if (score.anomalyFlag && !opts.allowAnomaly) {
    return { allowed: false, code: "ANOMALY_DETECTED" };
  }
  if (score.score < opts.minScore) {
    return { allowed: false, code: "SCORE_TOO_LOW" };
  }
  return { allowed: true };
}


// =============================================================================
// ScoreCache — the single-slot last-known-good store
// =============================================================================

export interface CachedScore {
  readonly score:    TrustScore;
  readonly cachedAt: number;       // ms-precision wall-clock when cached
}

/**
 * Last-known-good score cache for the VULN-12 fail-closed-with-cache path.
 *
 * A single slot per ScoreCache instance — one cache per agent_wallet. The
 * PluginState owns one cache (the plugin is single-agent).
 *
 * `put` is called on every successful score fetch (background refresh,
 * trust_gate's success branch, check_score action). `getIfFresh` is called
 * by trust_gate's network-error branch. `age` and `isFresh` use a caller-
 * supplied `now` to keep the cache deterministic in tests.
 *
 * TTL semantics:
 *   - `ttlMs > 0`: an entry is fresh while `now - cachedAt < ttlMs`.
 *   - `ttlMs == 0`: no cache freshness ever (disabled cache). Fail-closed
 *     unconditionally during blackouts — for the most paranoid deployments.
 */
export class ScoreCache {
  private entry: CachedScore | null = null;

  constructor(public readonly ttlMs: number) {
    if (ttlMs < 0 || !Number.isFinite(ttlMs)) {
      throw new Error(`ScoreCache.ttlMs must be a finite non-negative number, got ${ttlMs}`);
    }
  }

  /** Store the latest successfully-fetched score. */
  put(score: TrustScore, now: number = Date.now()): void {
    this.entry = { score, cachedAt: now };
  }

  /** The cached entry regardless of age, or null if never populated. */
  peek(): CachedScore | null {
    return this.entry;
  }

  /** Age in ms. Infinity when empty. */
  age(now: number = Date.now()): number {
    if (!this.entry) return Infinity;
    return now - this.entry.cachedAt;
  }

  /** True iff a cached entry exists and is younger than ttlMs. */
  isFresh(now: number = Date.now()): boolean {
    if (this.ttlMs === 0) return false;
    return this.age(now) < this.ttlMs;
  }

  /** The cached entry iff fresh, else null. The trust_gate uses this. */
  getIfFresh(now: number = Date.now()): CachedScore | null {
    return this.isFresh(now) ? this.entry : null;
  }

  /** Forget the cached entry. Used on shutdown / disposal. */
  clear(): void {
    this.entry = null;
  }
}
