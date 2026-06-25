// =============================================================================
// PHYLANX_AUTO_PAUSE_STATUS action (Day 42)
//
// Lets the agent introspect its own pause state in conversation:
//   user: "are you paused?"
//   agent: "Yes — paused 14 minutes ago due to ALERT_RED. Need 2 healthy
//          scores to resume; current streak is 0."
//
// Read-only — never triggers a fetch or mutates state. The background
// refresh loop in PluginState is what drives transitions.
// =============================================================================

import {
  type Action,
  type IAgentRuntime,
  type Memory,
  type HandlerCallback,
} from "@elizaos/core";

import { loadConfig } from "../config";
import { getOrInitState } from "../state";

export const autoPauseStatusAction: Action = {
  name: "PHYLANX_AUTO_PAUSE_STATUS",
  description: "Report whether the runtime is currently auto-paused by the Phylanx trust score.",
  similes: [
    "are you paused",
    "is the agent paused",
    "is the runtime halted",
    "phylanx pause status",
    "are you currently halted",
  ],

  examples: [
    [
      { user: "{{user1}}", content: { text: "Are you paused?" } },
      {
        user: "{{agentName}}",
        content: {
          text: "I'm active. Phylanx reports me as GREEN at 850/1000.",
          action: "PHYLANX_AUTO_PAUSE_STATUS",
        },
      },
    ],
  ],

  validate: async (runtime: IAgentRuntime): Promise<boolean> => {
    try {
      loadConfig(runtime);
      return true;
    } catch {
      return false;
    }
  },

  handler: async (
    runtime: IAgentRuntime,
    _message: Memory,
    _state,
    _options,
    callback?: HandlerCallback,
  ): Promise<boolean> => {
    const config = loadConfig(runtime);
    const state  = getOrInitState(runtime, config);
    const snap   = state.pauseSnapshot();

    let text: string;
    if (!snap.paused) {
      const sc = state.lastScore;
      text = sc
        ? `I'm active. Phylanx reports me as ${sc.alert} at ${sc.score}/1000.`
        : "I'm active. No Phylanx score has been fetched yet this session.";
    } else {
      const ageMin = snap.pausedSince
        ? Math.max(1, Math.round((Date.now() - snap.pausedSince) / 60_000))
        : null;
      const ageStr  = ageMin === null ? "" : ` ${ageMin} minute${ageMin === 1 ? "" : "s"} ago`;
      const need    = config.autoResumeEpochs;
      const have    = snap.healthyStreak;
      text =
        `I'm paused${ageStr} — reason: ${snap.reason ?? "UNKNOWN"}` +
        (snap.triggerScore != null ? ` (score ${snap.triggerScore}/1000)` : "") +
        `. Need ${need} consecutive healthy score${need === 1 ? "" : "s"} ` +
        `to resume; current streak is ${have}.`;
    }

    if (callback) {
      await callback({ text, action: "PHYLANX_AUTO_PAUSE_STATUS" });
    }
    return true;
  },
};
