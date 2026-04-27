// =============================================================================
// score_context provider — injects current Helixor score into the agent's
// prompt context.
//
// Why: the agent should KNOW its own score so it can mention it
// conversationally ("My current Helixor trust score is 850, GREEN.") and
// reason about its standing. Without a provider, the agent has to call the
// CHECK_TRUST_SCORE action explicitly every time.
//
// The provider returns a short string injected into the system prompt. The
// LLM then has this context for any conversation turn.
// =============================================================================

import {
  type IAgentRuntime,
  type Memory,
  type Provider,
  type State,
} from "@elizaos/core";

import { loadConfig } from "../config";
import { getOrInitState } from "../state";

export const scoreContextProvider: Provider = {
  get: async (runtime: IAgentRuntime, _message: Memory, _state?: State): Promise<string> => {
    let config;
    try {
      config = loadConfig(runtime);
    } catch {
      return ""; // plugin not configured — no context to add
    }

    const state = getOrInitState(runtime, config);

    // Use last cached score if recent (≤ refreshIntervalMs old) to avoid
    // adding latency to every prompt build. Background refresh keeps it warm.
    const fresh = state.lastScore
                && Date.now() - state.lastScoreFetchedAt < config.refreshIntervalMs;

    if (!fresh) {
      // One-shot fetch on cold cache, but never block forever
      try {
        await Promise.race([
          state.refreshScore(),
          new Promise((resolve) => setTimeout(resolve, 1500)),
        ]);
      } catch {
        // Swallow — we'll just emit empty context
      }
    }

    const score = state.lastScore;
    if (!score) return "";

    const lines = [
      `Helixor trust score: ${score.score}/1000 (${score.alert}).`,
      `Source: ${score.source}. Last updated: ${score.updatedAt
        ? new Date(score.updatedAt * 1000).toISOString()
        : "never"}.`,
    ];
    if (score.anomalyFlag) {
      lines.push(`⚠️ Anomaly flag is set — recent behavior diverges from baseline.`);
    }
    if (score.source === "provisional") {
      lines.push(`Score is provisional — first 24h since registration.`);
    }
    if (score.score < config.minScore) {
      lines.push(
        `Score is below the operator's configured minimum (${config.minScore}); ` +
        `financial actions will be blocked by HELIXOR_TRUST_GATE.`,
      );
    }

    return lines.join(" ");
  },
};
