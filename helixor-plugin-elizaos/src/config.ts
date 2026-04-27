// =============================================================================
// @elizaos/plugin-helixor — configuration
//
// Reads from runtime.getSetting() with explicit validation. Refuses to start
// if config is broken — better to fail loud at boot than silently misconfigure.
// =============================================================================

import type { IAgentRuntime } from "@elizaos/core";

export interface HelixorPluginConfig {
  /** Helixor API base URL — e.g. https://api.helixor.xyz */
  apiUrl: string;

  /** Agent's monitored hot wallet pubkey (base58). */
  agentWallet: string;

  /** Owner wallet pubkey (separate from agent — the operator's cold key). */
  ownerWallet: string;

  /** Minimum score required to proceed with financial actions. Default 600. */
  minScore: number;

  /** Whether to allow stale scores. Default false. */
  allowStale: boolean;

  /** Whether to allow anomaly-flagged scores. Default false. */
  allowAnomaly: boolean;

  /**
   * Keywords used to identify financial actions in the elizaOS action graph.
   * Plugin checks BOTH action.name AND action-tag metadata.
   */
  financialActions: string[];

  /** How often (ms) to refresh the cached score in the background. Default 60_000. */
  refreshIntervalMs: number;

  /** Optional Helixor API key (Bearer token) for authenticated tier. */
  apiKey?: string;

  /** Whether to log telemetry events to console. Default true. */
  enableTelemetry: boolean;
}

const DEFAULT_FINANCIAL_ACTIONS = [
  "SWAP_TOKEN", "TRANSFER_TOKEN", "LEND", "BORROW",
  "STAKE", "UNSTAKE", "BUY", "SELL", "TRADE",
  "OPEN_POSITION", "CLOSE_POSITION", "WITHDRAW", "DEPOSIT",
];

const PUBKEY_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

export class HelixorConfigError extends Error {
  constructor(msg: string) {
    super(`[Helixor] ${msg}`);
    this.name = "HelixorConfigError";
  }
}

export function loadConfig(runtime: IAgentRuntime): HelixorPluginConfig {
  const agentWallet = runtime.getSetting("SOLANA_PUBLIC_KEY");
  if (!agentWallet) {
    throw new HelixorConfigError(
      "SOLANA_PUBLIC_KEY is required. Add it to your character settings.",
    );
  }
  if (!PUBKEY_RE.test(agentWallet)) {
    throw new HelixorConfigError(
      `SOLANA_PUBLIC_KEY '${agentWallet}' is not a valid base58 Solana pubkey.`,
    );
  }

  const ownerWallet = runtime.getSetting("HELIXOR_OWNER_WALLET") || agentWallet;
  if (!PUBKEY_RE.test(ownerWallet)) {
    throw new HelixorConfigError(
      `HELIXOR_OWNER_WALLET '${ownerWallet}' is not a valid base58 Solana pubkey.`,
    );
  }

  const apiUrl = runtime.getSetting("HELIXOR_API_URL");
  if (!apiUrl) {
    throw new HelixorConfigError(
      "HELIXOR_API_URL is required. Set explicitly to avoid accidentally hitting mainnet.",
    );
  }
  if (!/^https?:\/\//.test(apiUrl)) {
    throw new HelixorConfigError(
      `HELIXOR_API_URL '${apiUrl}' must start with http:// or https://`,
    );
  }

  const minScore = parseIntOr(runtime.getSetting("HELIXOR_MIN_SCORE"), 600);
  if (minScore < 0 || minScore > 1000) {
    throw new HelixorConfigError(
      `HELIXOR_MIN_SCORE must be 0-1000, got ${minScore}.`,
    );
  }

  const refreshIntervalMs = parseIntOr(runtime.getSetting("HELIXOR_REFRESH_MS"), 60_000);
  if (refreshIntervalMs < 5_000) {
    throw new HelixorConfigError(
      `HELIXOR_REFRESH_MS must be ≥ 5000ms (got ${refreshIntervalMs}). Lower values waste API calls.`,
    );
  }

  const allowStale   = boolish(runtime.getSetting("HELIXOR_ALLOW_STALE"));
  const allowAnomaly = boolish(runtime.getSetting("HELIXOR_ALLOW_ANOMALY"));
  const enableTelemetry = boolish(runtime.getSetting("HELIXOR_TELEMETRY"), true);
  const apiKey = runtime.getSetting("HELIXOR_API_KEY") || undefined;

  // Custom financial action list (CSV) — falls back to defaults
  const customActions = runtime.getSetting("HELIXOR_FINANCIAL_ACTIONS");
  const financialActions = customActions
    ? customActions.split(",").map((s: string) => s.trim().toUpperCase()).filter(Boolean)
    : DEFAULT_FINANCIAL_ACTIONS;

  return {
    apiUrl:            apiUrl.replace(/\/+$/, ""),
    agentWallet,
    ownerWallet,
    minScore,
    allowStale,
    allowAnomaly,
    financialActions,
    refreshIntervalMs,
    apiKey,
    enableTelemetry,
  };
}

function parseIntOr(v: string | null | undefined, fallback: number): number {
  if (v == null || v === "") return fallback;
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}

function boolish(v: string | null | undefined, fallback = false): boolean {
  if (v == null || v === "") return fallback;
  return /^(1|true|yes|on)$/i.test(v);
}

export const FINANCIAL_ACTION_DEFAULTS = DEFAULT_FINANCIAL_ACTIONS;
