// =============================================================================
// trust_gate evaluator (Day 12 + VULN-12) — production-critical behaviors:
//
//   1. mode = "enforce" | "warn" | "observe"
//      - enforce: blocks on policy failure (default)
//      - warn:    logs + beacons but allows action through (rollout/canary mode)
//      - observe: completely transparent — beacons but never participates
//
//   2. fail_mode = "closed" | "open" (DISCOURAGED — see VULN-12)
//      - closed: when API is unreachable AND no fresh cache, BLOCK (default)
//      - open:   when API is unreachable AND no fresh cache, ALLOW
//                — legacy HA-degraded operation. The audit's preferred
//                  blackout path is the cache; this flag bypasses even that.
//
//   3. Telemetry beacons for every decision, including PII-stripped action_name
//      and block_reason. Server-side dedup via beacon_id.
//
//   4. VULN-12 — FAIL CLOSED WITH LAST-KNOWN-GOOD CACHE.
//      On a NETWORK_ERROR (or any unexpected throw from the SDK), we no
//      longer jump straight to the fail-mode decision. Instead:
//
//        a. Consult `state.scoreCache.getIfFresh(now)`. If a cached score
//           younger than PHYLANX_CACHE_TTL_MS (default 15min) exists, we
//           evaluate the local `applyPolicy` mirror against it.
//             - Policy passes → allow, emit `action_allowed_from_cache`.
//             - Policy fails  → block with the policy code, emit
//                               `action_blocked_from_cache`.
//        b. No fresh cache → emit `gate_fail_closed_no_cache` and honour
//           the fail_mode (default closed). This is the audit-mandated
//           DDoS-resistant path: a blackout no longer bypasses the gate
//           as long as the cache is fresh; once the cache expires the
//           agent is locked down rather than fail-opened.
// =============================================================================

import {
  type Evaluator,
  type IAgentRuntime,
  type Memory,
  type State,
} from "@elizaos/core";
import { PhylanxError } from "@phylanx/client/unsafe";

import { loadConfig } from "../config";
import { applyPolicy, type CachedScore } from "../score_cache";
import { getOrInitState } from "../state";


export const trustGateEvaluator: Evaluator = {
  name: "PHYLANX_TRUST_GATE",
  description:
    "Block financial actions when the agent's Phylanx trust score is " +
    "too low / stale / anomalous / deactivated.",
  similes: ["check trust before financial action"],
  alwaysRun: false,
  examples: [],

  validate: async (runtime: IAgentRuntime, message: Memory): Promise<boolean> => {
    let config;
    try {
      config = loadConfig(runtime);
    } catch {
      return false;
    }

    // observe mode: never participate. Run silently in the background only.
    if (config.mode === "observe") return false;

    const action = (message.content as { action?: string }).action?.toUpperCase();
    const text   = (message.content?.text ?? "").toLowerCase();

    if (action && config.financialActions.includes(action)) return true;

    if (!action) {
      const verbs = ["swap", "transfer", "stake", "lend", "borrow", "buy", "sell", "trade"];
      const wordRegex = new RegExp(`\\b(${verbs.join("|")})\\b`, "i");
      return wordRegex.test(text);
    }

    return false;
  },

  handler: async (
    runtime: IAgentRuntime,
    message: Memory,
    _state?: State,
  ): Promise<string> => {
    const config = loadConfig(runtime);
    const state  = getOrInitState(runtime, config);
    const action = (message.content as { action?: string }).action ?? "unknown";

    let scoreSnapshot: number | null = null;
    let alertSnapshot: "GREEN" | "YELLOW" | "RED" | null = null;

    try {
      const score = await state.client.requireMinScore(
        config.agentWallet,
        config.minScore,
        {
          allowStale:       config.allowStale,
          allowAnomaly:     config.allowAnomaly,
          allowProvisional: false,   // never overridable for financial actions
        },
      );

      state.recordScore(score);
      scoreSnapshot = score.score;
      alertSnapshot = score.alert;

      state.recordEvent("action_allowed", {
        action, score: score.score, alert: score.alert,
      });
      state.beacon.emit({
        event_type:    "action_allowed",
        agent_wallet:  config.agentWallet,
        character_name: runtime.character?.name,
        score:         score.score,
        alert_level:   score.alert,
        action_name:   action,
        extra: { mode: config.mode },
      });

      return `phylanx:allowed:${score.score}`;
    } catch (err) {
      // ── 1. Mapped policy failure (PhylanxError) ─────────────────────────
      if (err instanceof PhylanxError) {
        if (err.code === "NETWORK_ERROR") {
          // VULN-12: before deciding fail-open/closed, consult the cache.
          const cacheDecision = tryServeFromCache(
            state, config, action, err.message, runtime,
          );
          if (cacheDecision !== null) return cacheDecision;

          return failureWithoutCache(
            state, config, action, err.message,
          );
        }

        scoreSnapshot = err.score?.score ?? null;
        alertSnapshot = err.score?.alert ?? null;

        state.recordEvent("action_blocked", {
          action, code: err.code,
          score: scoreSnapshot, alert: alertSnapshot,
        });
        state.beacon.emit({
          event_type:     "action_blocked",
          agent_wallet:   config.agentWallet,
          character_name: runtime.character?.name,
          score:          scoreSnapshot ?? undefined,
          alert_level:    alertSnapshot ?? undefined,
          action_name:    action,
          block_reason:   err.code,
          extra: { mode: config.mode },
        });

        const rt = runtime as { emit?: (e: string, payload: unknown) => void };
        rt.emit?.("phylanx:blocked", {
          code:   err.code,
          score:  err.score,
          action,
          mode:   config.mode,
        });

        // mode="warn" → log it but let the action proceed
        if (config.mode === "warn") {
          // eslint-disable-next-line no-console
          console.warn(
            `[Phylanx] WARN-only mode: would block ${action} ` +
            `(${err.code}, score=${scoreSnapshot})`,
          );
          return `phylanx:warned:${err.code}`;
        }

        return `phylanx:blocked:${err.code}`;
      }

      // ── 2. Unexpected error (network, timeout, malformed response) ──────
      // Treat same as a NETWORK_ERROR for VULN-12 purposes: an unexpected
      // throw from the SDK might mean the API is down, malformed, or under
      // attack — exactly the blackout class the cache exists to survive.
      const errMsg = err instanceof Error ? err.message : String(err);
      state.recordEvent("gate_error", { action, error: errMsg });
      state.beacon.emit({
        event_type:    "gate_error",
        agent_wallet:  config.agentWallet,
        action_name:   action,
        error_message: errMsg.slice(0, 500),
        extra: { mode: config.mode, fail_mode: config.failMode },
      });

      const cacheDecision = tryServeFromCache(
        state, config, action, errMsg, runtime,
      );
      if (cacheDecision !== null) return cacheDecision;

      return failureWithoutCache(state, config, action, errMsg);
    }
  },
};


// =============================================================================
// VULN-12 helpers — fail-closed-with-last-known-good cache.
// =============================================================================

/**
 * Consult the last-known-good cache. Returns a handler return-string if the
 * cache was fresh enough to make a decision, or null if the caller should
 * fall through to {@link failureWithoutCache}.
 */
function tryServeFromCache(
  state:   ReturnType<typeof getOrInitState>,
  config:  ReturnType<typeof loadConfig>,
  action:  string,
  errMsg:  string,
  runtime: IAgentRuntime,
): string | null {
  const cached: CachedScore | null = state.scoreCache.getIfFresh();
  if (!cached) return null;

  const ageMs = state.scoreCache.age();
  const policy = applyPolicy(cached.score, {
    minScore:         config.minScore,
    allowStale:       config.allowStale,
    allowAnomaly:     config.allowAnomaly,
    allowProvisional: false,
  });

  if (policy.allowed) {
    state.recordEvent("action_allowed_from_cache", {
      action,
      score:        cached.score.score,
      alert:        cached.score.alert,
      cache_age_ms: ageMs,
    });
    state.beacon.emit({
      event_type:     "action_allowed_from_cache",
      agent_wallet:   config.agentWallet,
      character_name: runtime.character?.name,
      score:          cached.score.score,
      alert_level:    cached.score.alert,
      action_name:    action,
      extra: {
        mode:         config.mode,
        cache_age_ms: ageMs,
        error:        errMsg.slice(0, 200),
      },
    });
    // eslint-disable-next-line no-console
    console.warn(
      `[Phylanx] API unreachable — allowing ${action} from cache ` +
      `(score=${cached.score.score}, age=${ageMs}ms): ${errMsg}`,
    );
    return `phylanx:allowed:cache:${ageMs}`;
  }

  // Cache says BLOCK — the score in cache violates policy. Honour the policy.
  const code = policy.code ?? "SCORE_TOO_LOW";
  state.recordEvent("action_blocked_from_cache", {
    action,
    code,
    score:        cached.score.score,
    alert:        cached.score.alert,
    cache_age_ms: ageMs,
  });
  state.beacon.emit({
    event_type:     "action_blocked_from_cache",
    agent_wallet:   config.agentWallet,
    character_name: runtime.character?.name,
    score:          cached.score.score,
    alert_level:    cached.score.alert,
    action_name:    action,
    block_reason:   code,
    extra: {
      mode:         config.mode,
      cache_age_ms: ageMs,
      error:        errMsg.slice(0, 200),
    },
  });

  if (config.mode === "warn") {
    // eslint-disable-next-line no-console
    console.warn(
      `[Phylanx] WARN-only mode (cache): would block ${action} ` +
      `(${code}, score=${cached.score.score}, age=${ageMs}ms)`,
    );
    return `phylanx:warned:${code}:cache`;
  }
  return `phylanx:blocked:${code}:cache`;
}

/**
 * No fresh cache available — emit the audit-mandated DDoS-blackout beacon
 * and honour {@link PhylanxPluginConfig.failMode}. Default is fail-closed.
 */
function failureWithoutCache(
  state:  ReturnType<typeof getOrInitState>,
  config: ReturnType<typeof loadConfig>,
  action: string,
  errMsg: string,
): string {
  const cacheAgeMs = state.scoreCache.age();
  state.recordEvent("gate_fail_closed_no_cache", {
    action,
    fail_mode:    config.failMode,
    cache_age_ms: Number.isFinite(cacheAgeMs) ? cacheAgeMs : null,
    error:        errMsg,
  });
  state.beacon.emit({
    event_type:    "gate_fail_closed_no_cache",
    agent_wallet:  config.agentWallet,
    action_name:   action,
    error_message: errMsg.slice(0, 500),
    extra: {
      mode:         config.mode,
      fail_mode:    config.failMode,
      cache_age_ms: Number.isFinite(cacheAgeMs) ? cacheAgeMs : null,
    },
  });

  if (config.failMode === "open") {
    // eslint-disable-next-line no-console
    console.warn(
      `[Phylanx] gate blackout (fail-open) — allowing ${action}: ${errMsg}. ` +
      "VULN-12: this bypasses the audit-mandated cache path.",
    );
    return "phylanx:allowed:fail_open";
  }

  // Default: fail-closed — audit-mandated DDoS-resistant behaviour.
  // eslint-disable-next-line no-console
  console.warn(
    `[Phylanx] gate blackout (fail-closed, no cache) — blocking ${action}: ${errMsg}`,
  );
  return "phylanx:blocked:GATE_ERROR";
}
