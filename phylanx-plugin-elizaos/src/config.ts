// =============================================================================
// @elizaos/plugin-phylanx — configuration (Day 12 extensions + VULN-12)
//
// Adds:
//   PHYLANX_MODE          enforce | warn | observe   (default enforce)
//   PHYLANX_FAIL_MODE     closed  | open             (default closed)
//   PHYLANX_API_KEY       optional Bearer token for partner tier
//   PHYLANX_TELEMETRY_ENDPOINT  defaults to {api_url}/telemetry/beacon
//   PHYLANX_TELEMETRY_DISABLED  opt out entirely (default: enabled)
//   PHYLANX_CACHE_TTL_MS  VULN-12 — last-known-good cache TTL (default 15min).
//                         When the API is unreachable, the trust_gate uses a
//                         cached score that is younger than this TTL instead
//                         of failing closed (audit-mandated). Set to 0 to
//                         disable the cache and fail closed unconditionally.
// =============================================================================

import type { IAgentRuntime } from "@elizaos/core";

export type EnforceMode = "enforce" | "warn" | "observe";
export type FailMode    = "closed" | "open";

export interface PhylanxPluginConfig {
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

  // VULN-12 — last-known-good score cache TTL (ms). 0 disables the cache.
  cacheTtlMs:         number;

  // Day-42 — sticky auto-pause on RED. Different from the per-action gate:
  // once paused, the agent stays paused until it sees `autoResumeEpochs`
  // consecutive healthy score updates (default 2). Hysteresis prevents
  // single-epoch score noise from flapping the runtime open.
  autoPauseEnabled:   boolean;
  autoResumeEpochs:   number;
}

const DEFAULT_FINANCIAL_ACTIONS = [
  "SWAP_TOKEN", "TRANSFER_TOKEN", "LEND", "BORROW",
  "STAKE", "UNSTAKE", "BUY", "SELL", "TRADE",
  "OPEN_POSITION", "CLOSE_POSITION", "WITHDRAW", "DEPOSIT",
];

const PUBKEY_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

export class PhylanxConfigError extends Error {
  constructor(msg: string) {
    super(`[Phylanx] ${msg}`);
    this.name = "PhylanxConfigError";
  }
}

export function loadConfig(runtime: IAgentRuntime): PhylanxPluginConfig {
  const agentWallet = runtime.getSetting("SOLANA_PUBLIC_KEY");
  if (!agentWallet) {
    throw new PhylanxConfigError(
      "SOLANA_PUBLIC_KEY is required. Add it to your character settings.",
    );
  }
  if (!PUBKEY_RE.test(agentWallet)) {
    throw new PhylanxConfigError(
      `SOLANA_PUBLIC_KEY '${agentWallet}' is not a valid base58 Solana pubkey.`,
    );
  }

  const ownerWallet = runtime.getSetting("PHYLANX_OWNER_WALLET") ?? agentWallet;
  if (!PUBKEY_RE.test(ownerWallet)) {
    throw new PhylanxConfigError(
      `PHYLANX_OWNER_WALLET '${ownerWallet}' is not a valid base58 Solana pubkey.`,
    );
  }

  const apiUrl = runtime.getSetting("PHYLANX_API_URL");
  if (!apiUrl) {
    throw new PhylanxConfigError(
      "PHYLANX_API_URL is required. Set explicitly to avoid accidentally hitting mainnet.",
    );
  }
  if (!/^https?:\/\//.test(apiUrl)) {
    throw new PhylanxConfigError(
      `PHYLANX_API_URL '${apiUrl}' must start with http:// or https://`,
    );
  }

  const minScore = parseIntOr(runtime.getSetting("PHYLANX_MIN_SCORE"), 600);
  if (minScore < 0 || minScore > 1000) {
    throw new PhylanxConfigError(`PHYLANX_MIN_SCORE must be 0-1000, got ${minScore}.`);
  }

  const refreshIntervalMs = parseIntOr(runtime.getSetting("PHYLANX_REFRESH_MS"), 60_000);
  if (refreshIntervalMs < 5_000) {
    throw new PhylanxConfigError(
      `PHYLANX_REFRESH_MS must be ≥ 5000ms (got ${refreshIntervalMs}).`,
    );
  }

  // Mode controls what TRUST_GATE does on a policy failure
  const modeRaw = (runtime.getSetting("PHYLANX_MODE") ?? "enforce").toLowerCase();
  if (!["enforce", "warn", "observe"].includes(modeRaw)) {
    throw new PhylanxConfigError(
      `PHYLANX_MODE must be 'enforce', 'warn', or 'observe' (got '${modeRaw}').`,
    );
  }
  const mode = modeRaw as EnforceMode;

  // Fail mode controls what happens when the API is unreachable AND no
  // fresh cached score is available. VULN-12: the audit mandates fail-closed
  // in this state; `open` is accepted only for legacy/HA deployments that
  // explicitly opt into ungated operation during a blackout. A warning is
  // logged at load time so operators see the risk.
  const failRaw = (runtime.getSetting("PHYLANX_FAIL_MODE") ?? "closed").toLowerCase();
  if (!["closed", "open"].includes(failRaw)) {
    throw new PhylanxConfigError(
      `PHYLANX_FAIL_MODE must be 'closed' or 'open' (got '${failRaw}').`,
    );
  }
  const failMode = failRaw as FailMode;
  if (failMode === "open") {
    // eslint-disable-next-line no-console
    console.warn(
      "[Phylanx] PHYLANX_FAIL_MODE=open is DISCOURAGED — VULN-12 mitigation " +
      "is fail-closed-with-last-known-good cache. Setting fail_mode=open " +
      "lets a DDoS against phylanx-api bypass the trust gate.",
    );
  }

  // VULN-12 — last-known-good score cache TTL.
  // Default 15 minutes (audit-suggested). Floor at 0 (disabled); a value
  // below the API refresh interval is allowed but logged, since it makes
  // the cache useless during the very blackouts it exists for.
  const cacheTtlMs = parseIntOr(
    runtime.getSetting("PHYLANX_CACHE_TTL_MS"), 15 * 60 * 1000,
  );
  if (cacheTtlMs < 0) {
    throw new PhylanxConfigError(
      `PHYLANX_CACHE_TTL_MS must be >= 0 (got ${cacheTtlMs}).`,
    );
  }
  if (cacheTtlMs > 0 && cacheTtlMs < refreshIntervalMs) {
    // eslint-disable-next-line no-console
    console.warn(
      `[Phylanx] PHYLANX_CACHE_TTL_MS (${cacheTtlMs}ms) is shorter than ` +
      `PHYLANX_REFRESH_MS (${refreshIntervalMs}ms) — the cache will rarely ` +
      "hold a fresh entry during a blackout.",
    );
  }

  const allowStale       = boolish(runtime.getSetting("PHYLANX_ALLOW_STALE"));
  const allowAnomaly     = boolish(runtime.getSetting("PHYLANX_ALLOW_ANOMALY"));
  const enableTelemetry  = boolish(runtime.getSetting("PHYLANX_TELEMETRY"), true);
  const telemetryEnabled = !boolish(runtime.getSetting("PHYLANX_TELEMETRY_DISABLED"), false);
  const apiKey           = runtime.getSetting("PHYLANX_API_KEY") || undefined;

  // Day-42 sticky auto-pause. Default on (the YC pitch for the plugin is
  // "an agent runtime that consumes its own trust score") but operators
  // can disable it during dry-runs by setting PHYLANX_AUTO_PAUSE=false.
  const autoPauseEnabled = boolish(runtime.getSetting("PHYLANX_AUTO_PAUSE"), true);
  const autoResumeEpochs = parseIntOr(
    runtime.getSetting("PHYLANX_RECOVER_EPOCHS"), 2,
  );
  if (autoResumeEpochs < 1) {
    throw new PhylanxConfigError(
      `PHYLANX_RECOVER_EPOCHS must be >= 1 (got ${autoResumeEpochs}).`,
    );
  }

  const customActions    = runtime.getSetting("PHYLANX_FINANCIAL_ACTIONS");
  const financialActions = customActions
    ? customActions.split(",").map((s: string) => s.trim().toUpperCase()).filter(Boolean)
    : DEFAULT_FINANCIAL_ACTIONS;

  const apiUrlTrimmed = apiUrl.replace(/\/+$/, "");
  const telemetryEndpoint = runtime.getSetting("PHYLANX_TELEMETRY_ENDPOINT")
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
    cacheTtlMs,
    autoPauseEnabled, autoResumeEpochs,
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
