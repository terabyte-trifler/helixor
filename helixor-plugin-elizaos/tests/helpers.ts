// tests/helpers.ts — minimal mocks
import { vi } from "vitest";

const VALID_AGENT = "C6EiVB4Tiky14k8mtrK6EJ4FZN54pKCtcJstU7umhtjP";
const VALID_OWNER = "ANoJSqqxqih1kSkjYaRno9YeBMVaYB8gmcPnBdV5NqQJ";

export const VALID_WALLETS = { agent: VALID_AGENT, owner: VALID_OWNER };

export function makeRuntime(opts: { settings?: Record<string,string>; characterName?: string } = {}) {
  const settings: Record<string,string> = {
    SOLANA_PUBLIC_KEY:    VALID_AGENT,
    HELIXOR_OWNER_WALLET: VALID_OWNER,
    HELIXOR_API_URL:      "http://api.test.local",
    HELIXOR_MIN_SCORE:    "600",
    HELIXOR_REFRESH_MS:   "60000",
    HELIXOR_TELEMETRY:    "false",
    HELIXOR_TELEMETRY_DISABLED: "true",
    SOLANA_RPC_URL:       "http://rpc.test.local",
    ...opts.settings,
  };
  const events: Array<{ name: string; payload: unknown }> = [];
  return {
    agentId:   `mock-${Math.random().toString(36).slice(2)}`,
    character: { name: opts.characterName ?? "TestAgent" },
    getSetting: (k: string) => settings[k] ?? null,
    emit: (name: string, payload: unknown) => events.push({ name, payload }),
    on: () => {},
    _events: events,
    _settings: settings,
  };
}

export function scoreResponse(o: Record<string, any> = {}) {
  return {
    agent_wallet: VALID_AGENT,
    score: 850, alert: "GREEN", source: "live",
    success_rate: 97.0, anomaly_flag: false,
    updated_at: Math.floor(Date.now() / 1000),
    is_fresh: true,
    breakdown: {
      success_rate_score: 500, consistency_score: 300, stability_score: 50,
      raw_score: 850, guard_rail_applied: false,
    },
    served_at: Math.floor(Date.now() / 1000), cached: false,
    ...o,
  };
}

export function withGlobalFetch(handler: (url: string, init?: any) => any) {
  const original = globalThis.fetch;
  globalThis.fetch = vi.fn(async (url: any, init?: any) => {
    const result = await handler(String(url), init);
    return {
      ok: result.status >= 200 && result.status < 300,
      status: result.status,
      headers: new Headers(result.headers ?? {}),
      json: async () => result.body,
      text: async () => JSON.stringify(result.body),
    } as Response;
  }) as any;
  return () => { globalThis.fetch = original; };
}

/** Capture fetch calls for assertion. Returns calls[] + restore fn. */
export function captureFetch(handler?: (url: string, init?: any) => any) {
  const original = globalThis.fetch;
  const calls: Array<{ url: string; init: any }> = [];
  globalThis.fetch = vi.fn(async (url: any, init?: any) => {
    calls.push({ url: String(url), init });
    const result = handler ? await handler(String(url), init) : { status: 202, body: { accepted: true } };
    return {
      ok: result.status >= 200 && result.status < 300,
      status: result.status,
      headers: new Headers(result.headers ?? {}),
      json: async () => result.body,
      text: async () => JSON.stringify(result.body),
    } as Response;
  }) as any;
  return { calls, restore: () => { globalThis.fetch = original; } };
}
