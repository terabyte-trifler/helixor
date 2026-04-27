// =============================================================================
// HELIXOR_PREPARE_REGISTRATION action.
//
// When an agent isn't registered yet, this action returns a base64
// transaction the operator's wallet can sign + submit. Plugin never holds
// the owner's private key.
// =============================================================================

import {
  type Action,
  type HandlerCallback,
  type IAgentRuntime,
  type Memory,
} from "@elizaos/core";

import { loadConfig } from "../config";
import { getOrInitState } from "../state";
import { prepareRegistration } from "../registration";

export const prepareRegistrationAction: Action = {
  name: "HELIXOR_PREPARE_REGISTRATION",
  description: "Build an unsigned register_agent transaction the operator's wallet must sign.",
  similes: ["register me with helixor", "sign me up for helixor", "enroll in helixor"],
  examples: [],

  validate: async (runtime: IAgentRuntime): Promise<boolean> => {
    try { loadConfig(runtime); return true; } catch { return false; }
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

    const rpcUrl = runtime.getSetting("SOLANA_RPC_URL")
                ?? "https://api.devnet.solana.com";

    try {
      const prepared = await prepareRegistration({
        agentWallet: config.agentWallet,
        ownerWallet: config.ownerWallet,
        name:        runtime.character?.name ?? "elizaOS Agent",
        rpcUrl,
      });

      state.recordEvent("registration_prepared", {
        registrationPda: prepared.registrationPda,
      });

      if (callback) {
        await callback({
          text:
            `Registration transaction ready. Owner ${config.ownerWallet} must sign + submit.\n\n` +
            `Registration PDA: ${prepared.registrationPda}\n` +
            `Escrow vault PDA: ${prepared.escrowVaultPda}\n\n` +
            `Unsigned tx (base64): ${prepared.unsignedTxBase64.slice(0, 100)}...\n\n` +
            `Submit via your wallet within ~2 minutes (blockhash ${prepared.recentBlockhash.slice(0, 8)}...).`,
          action: "HELIXOR_PREPARE_REGISTRATION",
          // attachments: include full base64 here in a real elizaOS deployment
        });
      }
      return true;
    } catch (err) {
      state.recordEvent("registration_prepare_failed", { error: String(err) });
      if (callback) {
        await callback({
          text: `Failed to prepare Helixor registration: ${(err as Error).message}`,
          action: "HELIXOR_PREPARE_REGISTRATION",
        });
      }
      return false;
    }
  },
};
