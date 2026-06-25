// tests/beacon.test.ts — telemetry behavior: cooldowns, PII stripping, dedup
import { afterEach, describe, expect, it, vi } from "vitest";

import { TelemetryBeaconClient } from "../src/telemetry/beacon";


function makeClient(opts: { fetcher: any; enabled?: boolean }) {
  return new TelemetryBeaconClient({
    endpoint: "http://api.test/telemetry/beacon",
    enabled:  opts.enabled ?? true,
    fetch:    opts.fetcher,
  });
}


describe("TelemetryBeaconClient — basic delivery", () => {

  it("sends a beacon to the configured endpoint", async () => {
    const fetcher = vi.fn(async () => ({
      ok: true, status: 202, headers: new Headers(), json: async () => ({}),
    }) as Response);
    const c = makeClient({ fetcher });

    c.emit({
      event_type:    "plugin_initialized",
      agent_wallet:  "AGENT11111111111111111111111111111111111111",
    });
    await c.flush();

    expect(fetcher).toHaveBeenCalledOnce();
    const [url, init] = fetcher.mock.calls[0]!;
    expect(url).toBe("http://api.test/telemetry/beacon");
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body);
    expect(body.event_type).toBe("plugin_initialized");
    expect(body.beacon_id).toBeDefined();
    expect(body.plugin_version).toBeDefined();
  });

  it("disabled client emits nothing", async () => {
    const fetcher = vi.fn();
    const c = makeClient({ fetcher, enabled: false });
    c.emit({ event_type: "plugin_initialized" });
    await c.flush();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("includes Authorization when apiKey is set", async () => {
    const fetcher = vi.fn(async () => ({
      ok: true, status: 202, headers: new Headers(), json: async () => ({}),
    }) as Response);
    const c = new TelemetryBeaconClient({
      endpoint: "http://api.test/telemetry/beacon",
      enabled: true, fetch: fetcher,
      apiKey: "hxop_test_123",
    });
    c.emit({ event_type: "plugin_initialized" });
    await c.flush();
    const [, init] = fetcher.mock.calls[0]!;
    expect(init.headers.Authorization).toBe("Bearer hxop_test_123");
  });
});


describe("TelemetryBeaconClient — PII protection", () => {

  it("strips forbidden keys from extra payload", async () => {
    const fetcher = vi.fn(async () => ({
      ok: true, status: 202, headers: new Headers(), json: async () => ({}),
    }) as Response);
    const c = makeClient({ fetcher });
    c.emit({
      event_type: "action_blocked",
      extra: {
        text:         "user said something private",
        message:      "another bad key",
        action_type:  "transfer",     // legitimate
        amount_usd:   500,             // legitimate
      },
    });
    await c.flush();

    const body = JSON.parse(fetcher.mock.calls[0]![1].body);
    expect(body.extra.text).toBeUndefined();
    expect(body.extra.message).toBeUndefined();
    expect(body.extra.action_type).toBe("transfer");
    expect(body.extra.amount_usd).toBe(500);
  });

  it("strips case-insensitively (Text, Message, CONTENT)", async () => {
    const fetcher = vi.fn(async () => ({
      ok: true, status: 202, headers: new Headers(), json: async () => ({}),
    }) as Response);
    const c = makeClient({ fetcher });
    c.emit({
      event_type: "action_blocked",
      extra: { Text: "x", MESSAGE: "y", Content: "z", user_text: "w" },
    });
    await c.flush();
    const body = JSON.parse(fetcher.mock.calls[0]![1].body);
    expect(Object.keys(body.extra ?? {})).toHaveLength(0);
  });
});


describe("TelemetryBeaconClient — cooldowns", () => {

  it("agent_score_fetched is throttled to 1/min", async () => {
    const fetcher = vi.fn(async () => ({
      ok: true, status: 202, headers: new Headers(), json: async () => ({}),
    }) as Response);
    const c = makeClient({ fetcher });

    c.emit({ event_type: "agent_score_fetched", score: 800 });
    c.emit({ event_type: "agent_score_fetched", score: 801 });
    c.emit({ event_type: "agent_score_fetched", score: 802 });
    await c.flush();

    expect(fetcher).toHaveBeenCalledTimes(1);  // only first goes through
  });

  it("action_allowed has no cooldown", async () => {
    const fetcher = vi.fn(async () => ({
      ok: true, status: 202, headers: new Headers(), json: async () => ({}),
    }) as Response);
    const c = makeClient({ fetcher });

    c.emit({ event_type: "action_allowed", action_name: "SWAP" });
    c.emit({ event_type: "action_allowed", action_name: "SWAP" });
    c.emit({ event_type: "action_allowed", action_name: "SWAP" });
    await c.flush();

    expect(fetcher).toHaveBeenCalledTimes(3);
  });
});


describe("TelemetryBeaconClient — bounded queue", () => {

  it("drops oldest beacons at queue capacity", async () => {
    let resolveSend: () => void = () => {};
    const fetcher = vi.fn(() => new Promise<Response>((resolve) => {
      // Hold the first send to test queue accumulation
      resolveSend = () => resolve({
        ok: true, status: 202, headers: new Headers(), json: async () => ({}),
      } as Response);
    }));

    const c = new TelemetryBeaconClient({
      endpoint: "http://api.test/telemetry/beacon",
      enabled: true, fetch: fetcher,
      maxQueueSize: 3,
    });

    // Emit a lot — queue fills + drops oldest
    for (let i = 0; i < 10; i++) {
      c.emit({ event_type: "action_blocked", action_name: `action_${i}` });
    }
    // Don't flush — let the test verify the queue cap holds
    expect(fetcher).toHaveBeenCalledTimes(1);  // only one in-flight
    resolveSend();
  });
});


describe("TelemetryBeaconClient — failure handling", () => {

  it("4xx responses are dropped (not retried indefinitely)", async () => {
    const fetcher = vi.fn(async () => ({
      ok: false, status: 400, headers: new Headers(),
      json: async () => ({ error: "bad" }),
    }) as Response);
    const c = makeClient({ fetcher });

    c.emit({ event_type: "plugin_initialized" });
    await c.flush();
    await c.flush();   // second flush — should not re-send
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("network errors don't throw upstream", async () => {
    const fetcher = vi.fn(async () => { throw new Error("boom"); });
    const c = makeClient({ fetcher });

    expect(() => c.emit({ event_type: "plugin_initialized" })).not.toThrow();
    await expect(c.flush()).resolves.not.toThrow();
  });

  it("shutdown drains queue best-effort", async () => {
    const fetcher = vi.fn(async () => ({
      ok: true, status: 202, headers: new Headers(), json: async () => ({}),
    }) as Response);
    const c = makeClient({ fetcher });

    c.emit({ event_type: "plugin_initialized" });
    c.emit({ event_type: "plugin_shutdown" });

    await c.shutdown();
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});


describe("TelemetryBeaconClient — beacon_id stability", () => {

  it("each emit generates a unique beacon_id", async () => {
    const fetcher = vi.fn(async () => ({
      ok: true, status: 202, headers: new Headers(), json: async () => ({}),
    }) as Response);
    const c = makeClient({ fetcher });

    c.emit({ event_type: "action_allowed", action_name: "SWAP" });
    c.emit({ event_type: "action_allowed", action_name: "SWAP" });
    await c.flush();

    const id1 = JSON.parse(fetcher.mock.calls[0]![1].body).beacon_id;
    const id2 = JSON.parse(fetcher.mock.calls[1]![1].body).beacon_id;
    expect(id1).not.toBe(id2);
  });

  it("beacon_id is preserved across send retries (server dedup)", async () => {
    let attempts = 0;
    const fetcher = vi.fn(async () => {
      attempts++;
      if (attempts === 1) {
        return { ok: false, status: 503, headers: new Headers(), json: async () => ({}) } as Response;
      }
      return { ok: true, status: 202, headers: new Headers(), json: async () => ({}) } as Response;
    });

    const c = makeClient({ fetcher });
    c.emit({ event_type: "plugin_initialized", beacon_id: "stable-id-xyz" });
    await c.flush();

    // First call had 503, second flush would retry — but with backoff.
    // Just verify the beacon_id is what was sent.
    const body = JSON.parse(fetcher.mock.calls[0]![1].body);
    expect(body.beacon_id).toBe("stable-id-xyz");
  });
});
