// =============================================================================
// @elizaos/plugin-helixor — main entry point
//
// Wires up actions + evaluators + providers and runs an initialize() hook
// that bootstraps state.
//
// Two-line operator integration:
//
//   import { helixorPlugin } from "@elizaos/plugin-helixor";
//
//   export default {
//     name: "my-defi-agent",
//     plugins: [helixorPlugin],
//     settings: {
//       SOLANA_PUBLIC_KEY: "AGENT_HOT_WALLET",
//       HELIXOR_OWNER_WALLET: "OWNER_COLD_WALLET",  // optional
//       HELIXOR_API_URL:   "https://api.helixor.xyz",
//       HELIXOR_MIN_SCORE: "600",                    // optional
//     },
//   };
// =============================================================================

import { type IAgentRuntime, type Plugin } from "@elizaos/core";
import { AgentNotFoundError, HelixorError } from "@helixor/client";

import { checkTrustScoreAction } from "./actions/check_score";
import { prepareRegistrationAction } from "./actions/prepare_registration";
import { HelixorConfigError, loadConfig } from "./config";
import { trustGateEvaluator } from "./evaluators/trust_gate";
import { scoreContextProvider } from "./providers/score_context";
import { disposeState, getOrInitState } from "./state";

type InitializablePlugin = Plugin & {
  initialize?: (runtime: IAgentRuntime) => Promise<void>;
};

export const helixorPlugin: InitializablePlugin = {
  name: "helixor",
  description:
    "Helixor trust scoring — keeps a real-time score for the agent and " +
    "blocks financial actions when score falls below the configured minimum.",

  actions: [
    checkTrustScoreAction,
    prepareRegistrationAction,
  ],

  evaluators: [
    trustGateEvaluator,
  ],

  providers: [
    scoreContextProvider,
  ],

  // Most elizaOS versions look for an initialize() hook on the plugin.
  // We're defensive: also expose `start()` aliased.
  initialize: async (runtime: IAgentRuntime): Promise<void> => {
    let config;
    try {
      config = loadConfig(runtime);
    } catch (err) {
      if (err instanceof HelixorConfigError) {
        // eslint-disable-next-line no-console
        console.warn(err.message + " — plugin disabled for this character.");
        return;
      }
      throw err;
    }

    const state = getOrInitState(runtime, config);

    // eslint-disable-next-line no-console
    console.log(
      `[Helixor] plugin initialized. agent=${config.agentWallet} ` +
      `api=${config.apiUrl} minScore=${config.minScore}`,
    );

    // Initial fetch — surfaces "agent not registered" loud at boot
    try {
      const score = await state.client.getScore(config.agentWallet);
      state.lastScore = score;
      state.lastScoreFetchedAt = Date.now();
      // eslint-disable-next-line no-console
      console.log(
        `[Helixor] ✓ score=${score.score} alert=${score.alert} source=${score.source} ` +
        `fresh=${score.isFresh}`,
      );
      if (score.anomalyFlag) {
        // eslint-disable-next-line no-console
        console.warn("[Helixor] ⚠ anomaly_flag=true. Financial actions may be blocked.");
      }
      if (score.score < config.minScore) {
        // eslint-disable-next-line no-console
        console.warn(
          `[Helixor] ⚠ score (${score.score}) is below minimum (${config.minScore}). ` +
          `Financial actions will be blocked.`,
        );
      }
    } catch (err) {
      if (err instanceof AgentNotFoundError) {
        // eslint-disable-next-line no-console
        console.warn(
          "[Helixor] Agent not registered. Use the HELIXOR_PREPARE_REGISTRATION " +
          "action to build a registration tx for your wallet to sign.",
        );
        state.recordEvent("agent_not_registered", { agent: config.agentWallet });
      } else if (err instanceof HelixorError) {
        // eslint-disable-next-line no-console
        console.warn(`[Helixor] init fetch failed: ${err.code} (${err.message})`);
        state.recordEvent("init_fetch_failed", { code: err.code });
      } else {
        // eslint-disable-next-line no-console
        console.warn(`[Helixor] init fetch failed: ${(err as Error).message}`);
        state.recordEvent("init_fetch_failed", { error: String(err) });
      }
    }

    // Start the background refresh loop
    state.startRefreshLoop();

    // Cleanup hook for graceful shutdown
    const rt = runtime as { on?: (e: string, cb: () => void) => void };
    rt.on?.("shutdown", () => disposeState(runtime));
  },
};

// Re-exports for power users
export {
  checkTrustScoreAction,
  prepareRegistrationAction,
  trustGateEvaluator,
  scoreContextProvider,
};
export { loadConfig } from "./config";
export type { HelixorPluginConfig } from "./config";
export {
  derivePdas,
  prepareRegistration,
  submitRegistrationWithKeypair,
  RegistrationError,
} from "./registration";
export { getOrInitState, disposeState } from "./state";

export default helixorPlugin;
