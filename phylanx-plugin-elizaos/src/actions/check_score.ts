// =============================================================================
// CHECK_TRUST_SCORE action — lets users ask the agent for its score.
//
// Triggered by natural-language patterns like "what is your trust score" /
// "are you trusted" / "show me your phylanx score".
//
// Returns the score as a user-friendly memory the agent can respond with.
// =============================================================================

import {
  type Action,
  type IAgentRuntime,
  type Memory,
  type HandlerCallback,
} from "@elizaos/core";
import { PhylanxError } from "@phylanx/client/unsafe";

import { loadConfig } from "../config";
import { getOrInitState } from "../state";

export const checkTrustScoreAction: Action = {
  name: "PHYLANX_CHECK_TRUST_SCORE",
  description: "Read the agent's current Phylanx trust score.",
  similes: [
    "check trust score",
    "what is my trust score",
    "am I trusted",
    "phylanx score",
    "my reliability score",
  ],

  examples: [
    [
      { user: "{{user1}}", content: { text: "What is your trust score?" } },
      { user: "{{agentName}}", content: { text: "My Phylanx trust score is 850/1000 (GREEN).", action: "PHYLANX_CHECK_TRUST_SCORE" } },
    ],
  ],

  validate: async (runtime: IAgentRuntime): Promise<boolean> => {
    // Just check that the plugin is configured — don't crash on missing settings
    try {
      loadConfig(runtime);
      return true;
    } catch {
      return false;
    }
  },

  handler: async (
    runtime: IAgentRuntime,
    message: Memory,
    _state,
    _options,
    callback?: HandlerCallback,
  ): Promise<boolean> => {
    const config = loadConfig(runtime);
    const state  = getOrInitState(runtime, config);

    try {
      const score = await state.client.getScore(config.agentWallet);
      state.lastScore = score;
      state.lastScoreFetchedAt = Date.now();

      const text = formatScoreMessage(score, config);

      if (callback) {
        await callback({
          text,
          action: "PHYLANX_CHECK_TRUST_SCORE",
        });
      }

      state.recordEvent("score_queried_via_action", {
        score: score.score, alert: score.alert,
      });
      return true;
    } catch (err) {
      const text = err instanceof PhylanxError
        ? `I couldn't retrieve my Phylanx score (${err.code}).`
        : "I couldn't retrieve my Phylanx score right now.";

      if (callback) {
        await callback({ text, action: "PHYLANX_CHECK_TRUST_SCORE" });
      }
      state.recordEvent("score_query_failed", { error: String(err) });
      return false;
    }
  },
};

function formatScoreMessage(
  score: { score: number; alert: string; successRate: number; anomalyFlag: boolean; isFresh: boolean; source: string },
  config: { minScore: number },
): string {
  const alertEmoji = score.alert === "GREEN"  ? "🟢"
                   : score.alert === "YELLOW" ? "🟡" : "🔴";
  const minSuffix  = score.score >= config.minScore ? "" : ` (below operator minimum ${config.minScore})`;
  const stale      = score.isFresh ? "" : " (stale, >48h since update)";
  const anomaly    = score.anomalyFlag ? " ⚠️ Anomaly flagged." : "";
  const provisional = score.source === "provisional" ? " (provisional — first 24h)" : "";

  return `My Phylanx trust score is **${score.score}/1000** ${alertEmoji} ` +
         `${score.alert}${minSuffix}${stale}${provisional}. ` +
         `Recent success rate: ${score.successRate.toFixed(1)}%.${anomaly}`;
}
