// =============================================================================
// tests/helpers.ts — minimal mocks for elizaOS runtime + Helixor API.
// =============================================================================

import { vi } from "vitest";

const VALID_AGENT = "C6EiVB4Tiky14k8mtrK6EJ4FZN54pKCtcJstU7umhtjP";
const VALID_OWNER = "ANoJSqqxqih1kSkjYaRno9YeBMVaYB8gmcPnBdV5NqQJ";

export const VALID_WALLETS = { agent: VALID_AGENT, owner: VALID_OWNER };

interface MockRuntimeOptions {
  settings?: Record<string, string>;
  characterName?: string;
}

export function makeRuntime(opts: MockRuntimeOptions = {}) {
  const settings: Record<string, string> = {
    SOLANA_PUBLIC_KEY:    VALID_AGENT,
    HELIXOR_OWNER_WALLET: VALID_OWNER,
    HELIXOR_API_URL:      "http://api.test.local",
    HELIXOR_MIN_SCORE:    "600",
    HELIXOR_REFRESH_MS:   "60000",
    HELIXOR_TELEMETRY:    "false",
    SOLANA_RPC_URL:       "http://rpc.test.local",
    ...opts.settings,
  };

  const events: Array<{ name: string; payload: unknown }> = [];

  return {
    agentId:   `mock-agent-${Math.random().toString(36).slice(2)}`,
    character: { name: opts.characterName ?? "TestAgent" },
    getSetting: (key: string) => settings[key] ?? null,
    emit: (name: string, payload: unknown) => { events.push({ name, payload }); },
    on:   () => {},
    _events: events,
    _settings: settings,
  };
}

export function makeFetch(handler: (url: string) => any): typeof fetch {
  return vi.fn(async (url: any) => {
    const result = await handler(String(url));
    const headers = new Headers({
      "content-type": "application/json",
      "x-request-id": "test-1",
      ...(result.headers ?? {}),
    });
    return {
      ok:      result.status >= 200 && result.status < 300,
      status:  result.status,
      headers,
      json:    async () => result.body,
      text:    async () => JSON.stringify(result.body),
    } as Response;
  }) as unknown as typeof fetch;
}

export function scoreResponse(overrides: Record<string, any> = {}) {
  return {
    agent_wallet: VALID_AGENT,
    score:        850,
    alert:        "GREEN",
    source:       "live",
    success_rate: 97.0,
    anomaly_flag: false,
    updated_at:   Math.floor(Date.now() / 1000),
    is_fresh:     true,
    breakdown: {
      success_rate_score: 500,
      consistency_score:  300,
      stability_score:    50,
      raw_score:          850,
      guard_rail_applied: false,
    },
    served_at: Math.floor(Date.now() / 1000),
    cached:    false,
    ...overrides,
  };
}

/**
 * Inject a mock fetch into HelixorClient by monkey-patching globalThis.fetch.
 * The plugin creates its own HelixorClient internally (no fetch override
 * accessible through the plugin API), so we replace the global.
 */
export function withGlobalFetch(handler: (url: string) => any) {
  const original = globalThis.fetch;
  globalThis.fetch = makeFetch(handler);
  return () => { globalThis.fetch = original; };
}
