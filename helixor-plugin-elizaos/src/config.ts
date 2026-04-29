// =============================================================================
// @elizaos/plugin-helixor — configuration (Day 12 extensions)
//
// Adds:
//   HELIXOR_MODE          enforce | warn | observe   (default enforce)
//   HELIXOR_FAIL_MODE     closed  | open             (default closed)
//   HELIXOR_API_KEY       optional Bearer token for partner tier
//   HELIXOR_TELEMETRY_ENDPOINT  defaults to {api_url}/telemetry/beacon
//   HELIXOR_TELEMETRY_DISABLED  opt out entirely (default: enabled)
// =============================================================================

import type { IAgentRuntime } from "@elizaos/core";

export type EnforceMode = "enforce" | "warn" | "observe";
export type FailMode    = "closed" | "open";

export interface HelixorPluginConfig {
  apiUrl: string;
  agentWallet: string;
  ownerWallet: string;
  minScore: number;
  allowStale: boolean;
  allowAnomaly: boolean;
  financialActions: string[];
  refreshIntervalMs: number;
  apiKey?: string;
  enableTelemetry: boolean;

  // Day 12 additions
  mode:               EnforceMode;
  failMode:           FailMode;
  telemetryEnabled:   boolean;
  telemetryEndpoint:  string;
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

  const ownerWallet = runtime.getSetting("HELIXOR_OWNER_WALLET") ?? agentWallet;
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
    throw new HelixorConfigError(`HELIXOR_MIN_SCORE must be 0-1000, got ${minScore}.`);
  }

  const refreshIntervalMs = parseIntOr(runtime.getSetting("HELIXOR_REFRESH_MS"), 60_000);
  if (refreshIntervalMs < 5_000) {
    throw new HelixorConfigError(
      `HELIXOR_REFRESH_MS must be ≥ 5000ms (got ${refreshIntervalMs}).`,
    );
  }

  // Mode controls what TRUST_GATE does on a policy failure
  const modeRaw = (runtime.getSetting("HELIXOR_MODE") ?? "enforce").toLowerCase();
  if (!["enforce", "warn", "observe"].includes(modeRaw)) {
    throw new HelixorConfigError(
      `HELIXOR_MODE must be 'enforce', 'warn', or 'observe' (got '${modeRaw}').`,
    );
  }
  const mode = modeRaw as EnforceMode;

  // Fail mode controls what happens when API is unreachable
  const failRaw = (runtime.getSetting("HELIXOR_FAIL_MODE") ?? "closed").toLowerCase();
  if (!["closed", "open"].includes(failRaw)) {
    throw new HelixorConfigError(
      `HELIXOR_FAIL_MODE must be 'closed' or 'open' (got '${failRaw}').`,
    );
  }
  const failMode = failRaw as FailMode;

  const allowStale       = boolish(runtime.getSetting("HELIXOR_ALLOW_STALE"));
  const allowAnomaly     = boolish(runtime.getSetting("HELIXOR_ALLOW_ANOMALY"));
  const enableTelemetry  = boolish(runtime.getSetting("HELIXOR_TELEMETRY"), true);
  const telemetryEnabled = !boolish(runtime.getSetting("HELIXOR_TELEMETRY_DISABLED"), false);
  const apiKey           = runtime.getSetting("HELIXOR_API_KEY") || undefined;

  const customActions    = runtime.getSetting("HELIXOR_FINANCIAL_ACTIONS");
  const financialActions = customActions
    ? customActions.split(",").map((s: string) => s.trim().toUpperCase()).filter(Boolean)
    : DEFAULT_FINANCIAL_ACTIONS;

  const apiUrlTrimmed = apiUrl.replace(/\/+$/, "");
  const telemetryEndpoint = runtime.getSetting("HELIXOR_TELEMETRY_ENDPOINT")
                          ?? `${apiUrlTrimmed}/telemetry/beacon`;

  return {
    apiUrl:            apiUrlTrimmed,
    agentWallet, ownerWallet, minScore,
    allowStale, allowAnomaly,
    financialActions, refreshIntervalMs, apiKey,
    enableTelemetry,
    mode, failMode,
    telemetryEnabled,
    telemetryEndpoint,
  };
}

function parseIntOr(v: string | null | undefined, fallback: number): number {
  if (v == null || v === "") return fallback;
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}

function boolish(v: string | null | undefined, fallback = false): boolean {
  if (v == null) return fallback;
  return /^(1|true|yes|on)$/i.test(v);
}

export const FINANCIAL_ACTION_DEFAULTS = DEFAULT_FINANCIAL_ACTIONS;
