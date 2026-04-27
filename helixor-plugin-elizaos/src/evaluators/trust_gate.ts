// =============================================================================
// trust_gate evaluator — pre-action policy enforcement.
//
// elizaOS evaluators run at well-defined hooks in the action lifecycle.
// We hook into `validate()` which runs BEFORE the action executes — if it
// returns false, elizaOS halts the action.
//
// This is the actual gate. The spec attempted to detect financial actions
// via natural-language keyword matching ("swap" in user text) — that's
// fragile (matches "swap stories with you") and easily bypassed.
//
// Day 9's approach: register an evaluator with elizaOS that the host runtime
// invokes for any tagged action. The plugin reads `message.content.action`
// (the resolved action name) and matches against the configured financial
// action list. Falls back to text-keyword detection ONLY when no resolved
// action is present (older elizaOS versions).
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
  description: "Block financial actions when the agent's Helixor trust score is too low.",
  similes: ["check trust before financial action"],
  alwaysRun: false,
  examples: [],

  validate: async (runtime: IAgentRuntime, message: Memory): Promise<boolean> => {
    const config = loadConfig(runtime);
    const action = (message.content as { action?: string }).action?.toUpperCase();
    const text   = (message.content?.text ?? "").toLowerCase();

    // Primary: resolved action name (most reliable)
    if (action && config.financialActions.includes(action)) {
      return true;
    }

    // Fallback: only if no action resolved AND text strongly suggests financial intent.
    // We keep this narrow — only trigger on whole-word verb matches.
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

    try {
      const score = await state.client.requireMinScore(
        config.agentWallet,
        config.minScore,
        {
          allowStale:   config.allowStale,
          allowAnomaly: config.allowAnomaly,
          // Provisional NEVER allowed for financial actions — too risky
          allowProvisional: false,
        },
      );

      state.lastScore = score;
      state.lastScoreFetchedAt = Date.now();

      state.recordEvent("action_allowed", {
        action:         (message.content as { action?: string }).action,
        score:          score.score,
        alert:          score.alert,
        anomaly_flag:   score.anomalyFlag,
      });

      return `helixor:allowed:${score.score}`;
    } catch (err) {
      if (err instanceof HelixorError) {
        state.recordEvent("action_blocked", {
          action: (message.content as { action?: string }).action,
          code:   err.code,
          score:  err.score?.score ?? null,
          alert:  err.score?.alert ?? null,
        });

        // Surface as a runtime event so other plugins can react
        const rt = runtime as { emit?: (e: string, payload: unknown) => void };
        rt.emit?.("helixor:blocked", {
          code:   err.code,
          score:  err.score,
          action: (message.content as { action?: string }).action,
        });

        return `helixor:blocked:${err.code}`;
      }

      // Unexpected error — fail open or closed?
      // Closed (block) is the safe default. Operator can flip via setting.
      state.recordEvent("gate_error", { error: String(err) });
      return "helixor:blocked:GATE_ERROR";
    }
  },
};
