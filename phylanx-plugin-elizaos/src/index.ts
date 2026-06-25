// =============================================================================
// @elizaos/plugin-phylanx — main entry point (Day 12)
//
// New behaviors:
//   - initialize() retries score fetch with exponential backoff before
//     declaring "agent not registered" (handles transient API blips)
//   - Emits plugin_initialized beacon at startup with full env
//   - Emits plugin_shutdown beacon on graceful shutdown
//   - Attaches whoami CLI as `npx @elizaos/plugin-phylanx status`
// =============================================================================

import { type IAgentRuntime, type Plugin } from "@elizaos/core";
import { AgentNotFoundError, PhylanxError } from "@phylanx/client/unsafe";

import { autoPauseStatusAction } from "./actions/auto_pause_status";
import { checkTrustScoreAction } from "./actions/check_score";
import { prepareRegistrationAction } from "./actions/prepare_registration";
import { PhylanxConfigError, loadConfig } from "./config";
import { autoPauseEvaluator } from "./evaluators/auto_pause";
import { trustGateEvaluator } from "./evaluators/trust_gate";
import { scoreContextProvider } from "./providers/score_context";
import { disposeState, getOrInitState } from "./state";
import { PLUGIN_VERSION } from "./version";


const INIT_FETCH_RETRIES   = 3;
const INIT_RETRY_BACKOFF_MS = [1000, 3000, 9000];


type InitializablePlugin = Plugin & {
  initialize?: (runtime: IAgentRuntime) => Promise<void>;
};

export const phylanxPlugin: InitializablePlugin = {
  name: "phylanx",
  description:
    "Phylanx trust scoring — keeps a real-time score for the agent and " +
    "blocks financial actions when score falls below the configured minimum.",

  actions:    [checkTrustScoreAction, prepareRegistrationAction, autoPauseStatusAction],
  evaluators: [trustGateEvaluator, autoPauseEvaluator],
  providers:  [scoreContextProvider],

  initialize: async (runtime: IAgentRuntime): Promise<void> => {
    let config;
    try {
      config = loadConfig(runtime);
    } catch (err) {
      if (err instanceof PhylanxConfigError) {
        // eslint-disable-next-line no-console
        console.warn(err.message + " — plugin disabled for this character.");
        return;
      }
      throw err;
    }

    const state = getOrInitState(runtime, config);

    // eslint-disable-next-line no-console
    console.log(
      `[Phylanx] plugin v${PLUGIN_VERSION} initialized. ` +
      `agent=${config.agentWallet.slice(0,12)}... ` +
      `api=${config.apiUrl} ` +
      `mode=${config.mode} fail_mode=${config.failMode} ` +
      `minScore=${config.minScore}`,
    );

    // Beacon: announce startup before fetching score (so server records the
    // integration even if score fetch fails)
    state.beacon.emit({
      event_type:     "plugin_initialized",
      agent_wallet:   config.agentWallet,
      character_name: runtime.character?.name,
      extra: {
        mode:       config.mode,
        fail_mode:  config.failMode,
        min_score:  config.minScore,
        api_url:    config.apiUrl,
        has_api_key: Boolean(config.apiKey),
      },
    });

    // ── Initial score fetch with retry on transient failures ────────────
    let registered = false;
    let lastError: unknown = null;

    for (let attempt = 0; attempt < INIT_FETCH_RETRIES; attempt++) {
      try {
        const score = await state.client.getScore(config.agentWallet);
        state.lastScore = score;
        state.lastScoreFetchedAt = Date.now();
        registered = true;

        state.beacon.emit({
          event_type:     "agent_score_fetched",
          agent_wallet:   config.agentWallet,
          score:          score.score,
          alert_level:    score.alert,
        });

        // eslint-disable-next-line no-console
        console.log(
          `[Phylanx] ✓ agent score: ${score.score}/1000 (${score.alert}) ` +
          `source=${score.source} fresh=${score.isFresh}`,
        );
        if (score.anomalyFlag) {
          // eslint-disable-next-line no-console
          console.warn("[Phylanx] ⚠ anomaly_flag=true. Financial actions may be blocked.");
        }
        if (score.score < config.minScore) {
          // eslint-disable-next-line no-console
          console.warn(
            `[Phylanx] ⚠ score (${score.score}) < minimum (${config.minScore}). ` +
            (config.mode === "enforce"
              ? "Financial actions WILL be blocked."
              : config.mode === "warn"
                ? "Mode=warn → would block but allowing through with a warning."
                : "Mode=observe → no enforcement."),
          );
        }
        break;
      } catch (err) {
        lastError = err;
        if (err instanceof AgentNotFoundError) {
          // Permanent — don't retry
          // eslint-disable-next-line no-console
          console.warn(
            "[Phylanx] Agent not registered. Use the PHYLANX_PREPARE_REGISTRATION " +
            "action to build a registration tx for your wallet to sign.",
          );
          state.recordEvent("agent_not_registered", { agent: config.agentWallet });
          break;
        }
        if (attempt < INIT_FETCH_RETRIES - 1) {
          await new Promise(r => setTimeout(r, INIT_RETRY_BACKOFF_MS[attempt] ?? 9000));
        }
      }
    }

    if (!registered && !(lastError instanceof AgentNotFoundError)) {
      const msg = lastError instanceof Error ? lastError.message : String(lastError);
      // eslint-disable-next-line no-console
      console.warn(`[Phylanx] init fetch failed after ${INIT_FETCH_RETRIES} attempts: ${msg}`);
      state.recordEvent("init_fetch_failed", { error: msg });
      state.beacon.emit({
        event_type:    "gate_error",
        agent_wallet:  config.agentWallet,
        error_message: msg.slice(0, 500),
        extra: { phase: "initialize" },
      });
    }

    // Background refresh
    state.startRefreshLoop();

    // Graceful shutdown beacon
    const rt = runtime as { on?: (e: string, cb: () => void) => void };
    rt.on?.("shutdown", () => {
      state.beacon.emit({
        event_type:    "plugin_shutdown",
        agent_wallet:  config.agentWallet,
      });
      disposeState(runtime);
    });
  },
};

// Re-exports
export { autoPauseStatusAction } from "./actions/auto_pause_status";
export { checkTrustScoreAction } from "./actions/check_score";
export { prepareRegistrationAction } from "./actions/prepare_registration";
export { autoPauseEvaluator } from "./evaluators/auto_pause";
export { trustGateEvaluator } from "./evaluators/trust_gate";
export { scoreContextProvider } from "./providers/score_context";
export { loadConfig, type PhylanxPluginConfig } from "./config";
export { PLUGIN_VERSION } from "./version";
export {
  derivePdas, prepareRegistration, submitRegistrationWithKeypair, RegistrationError,
} from "./registration";
export { getOrInitState, disposeState, type PauseSnapshot } from "./state";
export { TelemetryBeaconClient } from "./telemetry/beacon";

export default phylanxPlugin;
