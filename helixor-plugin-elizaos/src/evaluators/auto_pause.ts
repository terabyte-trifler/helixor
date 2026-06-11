// =============================================================================
// auto_pause evaluator (Day 42) — sticky runtime-wide halt on RED.
//
// What's different from trust_gate?
//   trust_gate blocks individual financial actions on a low score, fetching
//   fresh data per-message. auto_pause is a STATE MACHINE driven by the
//   background score refresh: once the cluster says the agent is RED /
//   anomalous / deactivated / below operator minimum, the runtime is
//   paused, and ALL actions (financial or not) are refused until the
//   cluster has reported `autoResumeEpochs` consecutive healthy scores.
//
// Hysteresis matters: a single GREEN score after a RED one is not enough
// to lift the pause, because score noise around the tier boundary would
// otherwise let an agent flap between paused and live every epoch.
//
// The pause state is owned by PluginState (set in `recordScore`). This
// evaluator is the read-side: it reports the current state to the
// runtime + emits the runtime event `helixor:auto_paused` so downstream
// plugins / operators can react.
// =============================================================================

import {
  type Evaluator,
  type IAgentRuntime,
  type Memory,
} from "@elizaos/core";

import { loadConfig } from "../config";
import { getOrInitState } from "../state";

export const autoPauseEvaluator: Evaluator = {
  name: "HELIXOR_AUTO_PAUSE",
  description:
    "Sticky runtime-wide halt when the cluster reports the agent as RED, " +
    "anomalous, or deactivated. Held until autoResumeEpochs consecutive " +
    "healthy scores are observed.",
  similes: ["halt on bad score", "freeze runtime"],
  alwaysRun: true,
  examples: [],

  validate: async (runtime: IAgentRuntime): Promise<boolean> => {
    try {
      const config = loadConfig(runtime);
      return config.autoPauseEnabled;
    } catch {
      return false;
    }
  },

  handler: async (
    runtime: IAgentRuntime,
    _message: Memory,
  ): Promise<string> => {
    const config = loadConfig(runtime);
    const state  = getOrInitState(runtime, config);
    const snap   = state.pauseSnapshot();

    if (!snap.paused) return "helixor:active";

    const rt = runtime as { emit?: (e: string, payload: unknown) => void };
    rt.emit?.("helixor:auto_paused", {
      reason:        snap.reason,
      pausedSince:   snap.pausedSince,
      triggerScore:  snap.triggerScore,
      healthyStreak: snap.healthyStreak,
      needsStreak:   config.autoResumeEpochs,
    });

    return `helixor:auto_paused:${snap.reason ?? "UNKNOWN"}`;
  },
};
