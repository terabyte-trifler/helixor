// tests/config.test.ts — config validation incl. mode + fail_mode + telemetry
import { describe, expect, it } from "vitest";

import { HelixorConfigError, loadConfig } from "../src/config";
import { makeRuntime } from "./helpers";

describe("loadConfig", () => {
  it("default mode is enforce", () => {
    const cfg = loadConfig(makeRuntime() as any);
    expect(cfg.mode).toBe("enforce");
  });

  it("default fail_mode is closed", () => {
    const cfg = loadConfig(makeRuntime() as any);
    expect(cfg.failMode).toBe("closed");
  });

  it("accepts mode=warn", () => {
    const cfg = loadConfig(makeRuntime({ settings: { HELIXOR_MODE: "warn" } }) as any);
    expect(cfg.mode).toBe("warn");
  });

  it("accepts mode=observe", () => {
    const cfg = loadConfig(makeRuntime({ settings: { HELIXOR_MODE: "observe" } }) as any);
    expect(cfg.mode).toBe("observe");
  });

  it("rejects invalid mode", () => {
    expect(() =>
      loadConfig(makeRuntime({ settings: { HELIXOR_MODE: "bogus" } }) as any),
    ).toThrow(HelixorConfigError);
  });

  it("accepts fail_mode=open", () => {
    const cfg = loadConfig(makeRuntime({ settings: { HELIXOR_FAIL_MODE: "open" } }) as any);
    expect(cfg.failMode).toBe("open");
  });

  it("rejects invalid fail_mode", () => {
    expect(() =>
      loadConfig(makeRuntime({ settings: { HELIXOR_FAIL_MODE: "wat" } }) as any),
    ).toThrow(/must be 'closed' or 'open'/);
  });

  it("telemetry endpoint defaults to {api_url}/telemetry/beacon", () => {
    const cfg = loadConfig(makeRuntime({
      settings: { HELIXOR_API_URL: "http://example.com" },
    }) as any);
    expect(cfg.telemetryEndpoint).toBe("http://example.com/telemetry/beacon");
  });

  it("telemetry can be disabled", () => {
    const cfg = loadConfig(makeRuntime({
      settings: { HELIXOR_TELEMETRY_DISABLED: "true" },
    }) as any);
    expect(cfg.telemetryEnabled).toBe(false);
  });

  it("telemetry endpoint can be overridden", () => {
    const cfg = loadConfig(makeRuntime({
      settings: { HELIXOR_TELEMETRY_ENDPOINT: "http://my-collector.test/v1" },
    }) as any);
    expect(cfg.telemetryEndpoint).toBe("http://my-collector.test/v1");
  });

  it("apiKey is forwarded when set", () => {
    const cfg = loadConfig(makeRuntime({
      settings: { HELIXOR_API_KEY: "hxop_secret123" },
    }) as any);
    expect(cfg.apiKey).toBe("hxop_secret123");
  });
});
