// tests/auto_pause.test.ts — Day 42: sticky runtime-wide pause hysteresis.
//
// What we assert:
//   1. A RED / anomaly / deactivated / sub-min score trips the pause
//      and emits the auto_paused beacon.
//   2. While paused, the auto_pause evaluator returns a paused result
//      AND emits the helixor:auto_paused runtime event.
//   3. Hysteresis: a single GREEN score does NOT lift the pause.
//   4. `autoResumeEpochs` consecutive healthy scores lift the pause
//      and emit the auto_resumed beacon.
//   5. Mid-recovery interruption (any unhealthy score) resets the streak.
//   6. HELIXOR_AUTO_PAUSE=false disables the whole machine.

import { afterEach, describe, expect, it, vi } from "vitest";

import type { TrustScore } from "@helixor/client";

import { autoPauseStatusAction } from "../src/actions/auto_pause_status";
import { loadConfig } from "../src/config";
import { autoPauseEvaluator } from "../src/evaluators/auto_pause";
import { getOrInitState } from "../src/state";
import { makeRuntime } from "./helpers";


function ts(overrides: Partial<TrustScore> = {}): TrustScore {
  return {
    agentWallet: "C6EiVB4Tiky14k8mtrK6EJ4FZN54pKCtcJstU7umhtjP",
    score:       850, alert: "GREEN", source: "live",
    successRate: 97, anomalyFlag: false, isFresh: true,
    updatedAt:   Math.floor(Date.now() / 1000),
    servedAt:    Math.floor(Date.now() / 1000), cached: false,
    ...overrides,
  };
}

const capturedBeacons: any[] = [];

function withBeaconCapture() {
  const original = globalThis.fetch;
  capturedBeacons.length = 0;
  globalThis.fetch = vi.fn(async (url: any, init?: any) => {
    const u = String(url);
    if (u.includes("/telemetry/beacon") && init?.body) {
      try { capturedBeacons.push(JSON.parse(init.body)); } catch { /* ignore */ }
    }
    return {
      ok: true, status: 202, headers: new Headers(),
      json: async () => ({ accepted: true }),
      text: async () => "{}",
    } as Response;
  }) as any;
  return () => { globalThis.fetch = original; };
}

async function flushBeacons(): Promise<void> {
  for (let i = 0; i < 5; i++) await new Promise(r => setTimeout(r, 5));
}


describe("AUTO_PAUSE — trigger conditions", () => {
  let restore: () => void = () => {};
  afterEach(() => restore());

  it("RED score trips pause and emits auto_paused beacon", async () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime({
      settings: { HELIXOR_TELEMETRY: "true", HELIXOR_TELEMETRY_DISABLED: "false" },
    });
    const state = getOrInitState(runtime as any, loadConfig(runtime as any));

    state.recordScore(ts({ score: 120, alert: "RED" }));

    expect(state.paused).toBe(true);
    expect(state.pausedReason).toBe("ALERT_RED");
    expect(state.pausedScore).toBe(120);

    await flushBeacons();
    const beacon = capturedBeacons.find(b => b.event_type === "auto_paused");
    expect(beacon).toBeDefined();
    expect(beacon.block_reason).toBe("ALERT_RED");
    expect(beacon.score).toBe(120);
  });

  it("anomaly flag trips pause even with a GREEN alert", async () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime();
    const state = getOrInitState(runtime as any, loadConfig(runtime as any));

    state.recordScore(ts({ score: 820, alert: "GREEN", anomalyFlag: true }));

    expect(state.paused).toBe(true);
    expect(state.pausedReason).toBe("ANOMALY_FLAGGED");
  });

  it("deactivated source trips pause regardless of score", async () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime();
    const state = getOrInitState(runtime as any, loadConfig(runtime as any));

    state.recordScore(ts({ score: 999, alert: "GREEN", source: "deactivated" }));

    expect(state.paused).toBe(true);
    expect(state.pausedReason).toBe("AGENT_DEACTIVATED");
  });

  it("sub-min score trips pause even with a YELLOW alert", async () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime({ settings: { HELIXOR_MIN_SCORE: "700" } });
    const state = getOrInitState(runtime as any, loadConfig(runtime as any));

    state.recordScore(ts({ score: 650, alert: "YELLOW" }));

    expect(state.paused).toBe(true);
    expect(state.pausedReason).toBe("SCORE_BELOW_MIN");
  });

  it("healthy score does NOT trip pause", () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime();
    const state = getOrInitState(runtime as any, loadConfig(runtime as any));

    state.recordScore(ts({ score: 850, alert: "GREEN" }));

    expect(state.paused).toBe(false);
    expect(state.pausedReason).toBeNull();
  });
});


describe("AUTO_PAUSE — hysteresis recovery", () => {
  let restore: () => void = () => {};
  afterEach(() => restore());

  it("single GREEN after pause does NOT auto-resume (needs autoResumeEpochs)", async () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime();   // default HELIXOR_RECOVER_EPOCHS = 2
    const state = getOrInitState(runtime as any, loadConfig(runtime as any));

    state.recordScore(ts({ score: 100, alert: "RED" }));
    expect(state.paused).toBe(true);

    state.recordScore(ts({ score: 850, alert: "GREEN" }));
    expect(state.paused).toBe(true);   // still paused — streak=1, needs 2
    expect(state.healthyStreak).toBe(1);
  });

  it("two consecutive GREEN scores resume the runtime", async () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime({
      settings: { HELIXOR_TELEMETRY: "true", HELIXOR_TELEMETRY_DISABLED: "false" },
    });
    const state = getOrInitState(runtime as any, loadConfig(runtime as any));

    state.recordScore(ts({ score: 100, alert: "RED" }));
    state.recordScore(ts({ score: 850, alert: "GREEN" }));
    state.recordScore(ts({ score: 870, alert: "GREEN" }));

    expect(state.paused).toBe(false);
    expect(state.pausedReason).toBeNull();
    expect(state.healthyStreak).toBe(0);

    await flushBeacons();
    const resumed = capturedBeacons.find(b => b.event_type === "auto_resumed");
    expect(resumed).toBeDefined();
    expect(resumed.extra.healthy_streak).toBe(2);
  });

  it("any unhealthy score mid-recovery resets the streak", () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime();
    const state = getOrInitState(runtime as any, loadConfig(runtime as any));

    state.recordScore(ts({ score: 100, alert: "RED" }));
    state.recordScore(ts({ score: 850, alert: "GREEN" }));
    expect(state.healthyStreak).toBe(1);

    state.recordScore(ts({ score: 850, alert: "GREEN", anomalyFlag: true }));
    expect(state.paused).toBe(true);
    expect(state.healthyStreak).toBe(0);

    state.recordScore(ts({ score: 850, alert: "GREEN" }));
    state.recordScore(ts({ score: 860, alert: "GREEN" }));
    expect(state.paused).toBe(false);
  });

  it("HELIXOR_RECOVER_EPOCHS=1 resumes immediately on first healthy score", () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime({ settings: { HELIXOR_RECOVER_EPOCHS: "1" } });
    const state = getOrInitState(runtime as any, loadConfig(runtime as any));

    state.recordScore(ts({ score: 100, alert: "RED" }));
    state.recordScore(ts({ score: 850, alert: "GREEN" }));

    expect(state.paused).toBe(false);
  });

  it("provisional score does not count as healthy", () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime();
    const state = getOrInitState(runtime as any, loadConfig(runtime as any));

    state.recordScore(ts({ score: 100, alert: "RED" }));
    state.recordScore(ts({ score: 850, alert: "GREEN", source: "provisional" }));

    expect(state.paused).toBe(true);
    expect(state.healthyStreak).toBe(0);
  });
});


describe("AUTO_PAUSE — evaluator surface", () => {
  let restore: () => void = () => {};
  afterEach(() => restore());

  it("evaluator returns helixor:active when not paused", async () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime();
    const r = await autoPauseEvaluator.handler(runtime as any, {} as any);
    expect(r).toBe("helixor:active");
  });

  it("evaluator emits helixor:auto_paused runtime event when paused", async () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime();
    const state = getOrInitState(runtime as any, loadConfig(runtime as any));
    state.recordScore(ts({ score: 100, alert: "RED" }));

    const r = await autoPauseEvaluator.handler(runtime as any, {} as any);
    expect(r).toBe("helixor:auto_paused:ALERT_RED");

    const ev = runtime._events.find(e => e.name === "helixor:auto_paused");
    expect(ev).toBeDefined();
    expect((ev!.payload as any).reason).toBe("ALERT_RED");
    expect((ev!.payload as any).needsStreak).toBe(2);
  });

  it("HELIXOR_AUTO_PAUSE=false disables the whole machine", async () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime({ settings: { HELIXOR_AUTO_PAUSE: "false" } });
    const state = getOrInitState(runtime as any, loadConfig(runtime as any));

    state.recordScore(ts({ score: 100, alert: "RED" }));
    expect(state.paused).toBe(false);

    const valid = await autoPauseEvaluator.validate(runtime as any, {} as any);
    expect(valid).toBe(false);
  });
});


describe("AUTO_PAUSE — status action", () => {
  let restore: () => void = () => {};
  afterEach(() => restore());

  it("active status reads the last score", async () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime();
    const state = getOrInitState(runtime as any, loadConfig(runtime as any));
    state.recordScore(ts({ score: 880, alert: "GREEN" }));

    let captured = "";
    await autoPauseStatusAction.handler(
      runtime as any, {} as any, undefined, undefined,
      async (msg: any) => { captured = msg.text; return [] as any; },
    );
    expect(captured).toContain("active");
    expect(captured).toContain("880");
  });

  it("paused status reports reason and recovery progress", async () => {
    restore = withBeaconCapture();
    const runtime = makeRuntime();
    const state = getOrInitState(runtime as any, loadConfig(runtime as any));
    state.recordScore(ts({ score: 100, alert: "RED" }));
    state.recordScore(ts({ score: 850, alert: "GREEN" }));   // streak=1, still paused

    let captured = "";
    await autoPauseStatusAction.handler(
      runtime as any, {} as any, undefined, undefined,
      async (msg: any) => { captured = msg.text; return [] as any; },
    );
    expect(captured).toContain("paused");
    expect(captured).toContain("ALERT_RED");
    expect(captured).toMatch(/streak is 1/);
  });
});
