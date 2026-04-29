// =============================================================================
// trust_gate evaluator (Day 12) — adds three production-critical behaviors:
//
//   1. mode = "enforce" | "warn" | "observe"
//      - enforce: blocks on policy failure (default)
//      - warn:    logs + beacons but allows action through (rollout/canary mode)
//      - observe: completely transparent — beacons but never participates
//
//   2. fail_mode = "closed" | "open"
//      - closed: when API is unreachable or unexpected error, BLOCK (default)
//      - open:   when API is unreachable, ALLOW (HA-degraded operation)
//
//   3. Telemetry beacons for every decision, including PII-stripped action_name
//      and block_reason. Server-side dedup via beacon_id.
// =============================================================================

import {
  type Evaluator,
  type IAgentRuntime,
  type Memory,
  type State,
} from "@elizaos/core";
import { HelixorError } from "@helixor/client";

import { loadConfig } from "../config";
import { getOrInitState } from "../state";


export const trustGateEvaluator: Evaluator = {
  name: "HELIXOR_TRUST_GATE",
  description:
    "Block financial actions when the agent's Helixor trust score is " +
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

      state.lastScore = score;
      state.lastScoreFetchedAt = Date.now();
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

      return `helixor:allowed:${score.score}`;
    } catch (err) {
      // ── 1. Mapped policy failure (HelixorError) ─────────────────────────
      if (err instanceof HelixorError) {
        if (err.code === "NETWORK_ERROR") {
          state.recordEvent("gate_error", { action, error: err.message });
          state.beacon.emit({
            event_type:    "gate_error",
            agent_wallet:  config.agentWallet,
            action_name:   action,
            error_message: err.message.slice(0, 500),
            extra: { mode: config.mode, fail_mode: config.failMode },
          });

          if (config.failMode === "open") {
            // eslint-disable-next-line no-console
            console.warn(
              `[Helixor] gate_error (fail-open) — allowing ${action}: ${err.message}`,
            );
            return "helixor:allowed:fail_open";
          }

          // eslint-disable-next-line no-console
          console.warn(
            `[Helixor] gate_error (fail-closed) — blocking ${action}: ${err.message}`,
          );
          return "helixor:blocked:GATE_ERROR";
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
        rt.emit?.("helixor:blocked", {
          code:   err.code,
          score:  err.score,
          action,
          mode:   config.mode,
        });

        // mode="warn" → log it but let the action proceed
        if (config.mode === "warn") {
          // eslint-disable-next-line no-console
          console.warn(
            `[Helixor] WARN-only mode: would block ${action} ` +
            `(${err.code}, score=${scoreSnapshot})`,
          );
          return `helixor:warned:${err.code}`;
        }

        return `helixor:blocked:${err.code}`;
      }

      // ── 2. Unexpected error (network, timeout, malformed response) ──────
      const errMsg = err instanceof Error ? err.message : String(err);
      state.recordEvent("gate_error", { action, error: errMsg });
      state.beacon.emit({
        event_type:    "gate_error",
        agent_wallet:  config.agentWallet,
        action_name:   action,
        error_message: errMsg.slice(0, 500),
        extra: { mode: config.mode, fail_mode: config.failMode },
      });

      // fail_mode="open" → degraded operation: allow
      if (config.failMode === "open") {
        // eslint-disable-next-line no-console
        console.warn(
          `[Helixor] gate_error (fail-open) — allowing ${action}: ${errMsg}`,
        );
        return "helixor:allowed:fail_open";
      }

      // Default: fail-closed — block on any unexpected error
      // eslint-disable-next-line no-console
      console.warn(
        `[Helixor] gate_error (fail-closed) — blocking ${action}: ${errMsg}`,
      );
      return "helixor:blocked:GATE_ERROR";
    }
  },
};
