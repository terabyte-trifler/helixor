// =============================================================================
// tests/state.test.ts — PluginState behaviour
// =============================================================================

import { afterEach, describe, expect, it } from "vitest";

import { loadConfig } from "../src/config";
import { disposeState, getOrInitState, PluginState } from "../src/state";
import { makeRuntime, scoreResponse, withGlobalFetch } from "./helpers";

describe("getOrInitState", () => {

  it("returns the same instance for the same runtime", () => {
    const runtime = makeRuntime();
    const cfg = loadConfig(runtime as any);
    const a = getOrInitState(runtime as any, cfg);
    const b = getOrInitState(runtime as any, cfg);
    expect(a).toBe(b);
  });

  it("returns different instances for different runtimes", () => {
    const r1 = makeRuntime();
    const r2 = makeRuntime();
    const cfg = loadConfig(r1 as any);
    const a = getOrInitState(r1 as any, cfg);
    const b = getOrInitState(r2 as any, cfg);
    expect(a).not.toBe(b);
  });

});


describe("PluginState.refreshScore", () => {
  let restore: () => void = () => {};
  afterEach(() => restore());

  it("populates lastScore on success", async () => {
    restore = withGlobalFetch(() => ({ status: 200, body: scoreResponse({ score: 800 }) }));

    const runtime = makeRuntime();
    const cfg = loadConfig(runtime as any);
    const state = getOrInitState(runtime as any, cfg);

    const score = await state.refreshScore();
    expect(score).not.toBeNull();
    expect(state.lastScore?.score).toBe(800);
    expect(state.lastScoreFetchedAt).toBeGreaterThan(0);
  });

  it("emits score_changed when score moves", async () => {
    let scoreVal = 800;
    restore = withGlobalFetch(() => ({ status: 200, body: scoreResponse({ score: scoreVal }) }));

    const runtime = makeRuntime();
    const cfg = loadConfig(runtime as any);
    const state = getOrInitState(runtime as any, cfg);

    await state.refreshScore();
    scoreVal = 750;
    await state.refreshScore();

    const events = state.getTelemetry();
    const changed = events.find(e => e.type === "score_changed");
    expect(changed).toBeDefined();
    expect((changed!.data as any).from).toBe(800);
    expect((changed!.data as any).to).toBe(750);
    expect((changed!.data as any).delta).toBe(-50);
  });

  it("emits anomaly_detected on transition false → true", async () => {
    let anomaly = false;
    restore = withGlobalFetch(() => ({ status: 200, body: scoreResponse({ anomaly_flag: anomaly }) }));

    const runtime = makeRuntime();
    const cfg = loadConfig(runtime as any);
    const state = getOrInitState(runtime as any, cfg);

    await state.refreshScore();
    anomaly = true;
    await state.refreshScore();

    expect(state.getTelemetry().some(e => e.type === "anomaly_detected")).toBe(true);
  });

  it("emits agent_deactivated when source flips", async () => {
    let source = "live";
    restore = withGlobalFetch(() => ({ status: 200, body: scoreResponse({ source }) }));

    const runtime = makeRuntime();
    const cfg = loadConfig(runtime as any);
    const state = getOrInitState(runtime as any, cfg);

    await state.refreshScore();
    source = "deactivated";
    await state.refreshScore();

    expect(state.getTelemetry().some(e => e.type === "agent_deactivated")).toBe(true);
  });

  it("on failure, populates lastError and emits refresh_failed", async () => {
    restore = withGlobalFetch(() => ({ status: 500, body: { error: "boom" } }));

    const runtime = makeRuntime();
    const cfg = loadConfig(runtime as any);
    const state = getOrInitState(runtime as any, cfg);

    const result = await state.refreshScore();
    expect(result).toBeNull();
    expect(state.lastError).not.toBeNull();
    expect(state.getTelemetry().some(e => e.type === "refresh_failed")).toBe(true);
  });
});


describe("PluginState refresh loop", () => {
  it("startRefreshLoop is idempotent", () => {
    const runtime = makeRuntime();
    const cfg = loadConfig(runtime as any);
    const state = getOrInitState(runtime as any, cfg);

    state.startRefreshLoop();
    state.startRefreshLoop();   // no error, no double-timer
    state.stopRefreshLoop();
    expect(true).toBe(true);
  });

  it("disposeState cleans up", () => {
    const runtime = makeRuntime();
    const cfg = loadConfig(runtime as any);
    const state = getOrInitState(runtime as any, cfg);
    state.startRefreshLoop();
    disposeState(runtime as any);
    // No assertion beyond "doesn't throw" — internal map state
    expect(true).toBe(true);
  });
});


describe("Telemetry buffer cap", () => {
  it("bounded to 100 events", () => {
    const runtime = makeRuntime();
    const cfg = loadConfig(runtime as any);
    const state = getOrInitState(runtime as any, cfg);

    for (let i = 0; i < 150; i++) {
      state.recordEvent("test", { i });
    }
    expect(state.getTelemetry().length).toBeLessThanOrEqual(100);
  });
});
