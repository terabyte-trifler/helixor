// =============================================================================
// @elizaos/plugin-helixor — plugin state (singleton)
//
// One HelixorClient per plugin instance, shared across actions, evaluators,
// providers. Avoids creating a fresh client (and fresh cache) on every call.
// =============================================================================

import { HelixorClient, type TrustScore } from "@helixor/client";

import type { HelixorPluginConfig } from "./config";

interface TelemetryEvent {
  type:      string;
  timestamp: number;
  data:      Record<string, unknown>;
}

export class PluginState {
  public readonly client: HelixorClient;
  public readonly config: HelixorPluginConfig;

  /** Most recently seen score — for proactive providers. */
  public lastScore: TrustScore | null = null;
  public lastScoreFetchedAt: number = 0;
  public lastError: Error | null = null;

  /** Telemetry buffer (last N events) for /helixor/status admin queries. */
  private readonly telemetry: TelemetryEvent[] = [];
  private readonly maxTelemetry = 100;

  /** Background refresh handle (null when not running). */
  private refreshTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: HelixorPluginConfig) {
    this.config = config;
    this.client = new HelixorClient({
      apiBase:    config.apiUrl,
      apiKey:     config.apiKey,
      timeoutMs:  5_000,
      maxRetries: 2,
      cacheTtlMs: 30_000,
    });
  }

  /** Start background score polling. Idempotent. */
  startRefreshLoop(): void {
    if (this.refreshTimer) return;

    this.refreshTimer = setInterval(() => {
      this.refreshScore().catch((err) => {
        this.recordEvent("refresh_failed", { error: String(err) });
      });
    }, this.config.refreshIntervalMs);

    // Don't keep Node's event loop alive just for this timer
    if (typeof this.refreshTimer === "object" && "unref" in this.refreshTimer) {
      (this.refreshTimer as { unref?: () => void }).unref?.();
    }
  }

  stopRefreshLoop(): void {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  async refreshScore(): Promise<TrustScore | null> {
    try {
      // Bypass client cache so we get a fresh value
      this.client.invalidate(this.config.agentWallet);
      const score = await this.client.getScore(this.config.agentWallet);

      const previous = this.lastScore;
      this.lastScore = score;
      this.lastScoreFetchedAt = Date.now();
      this.lastError = null;

      // Emit useful state-change events
      if (previous && previous.score !== score.score) {
        this.recordEvent("score_changed", {
          from: previous.score,
          to:   score.score,
          delta: score.score - previous.score,
        });
      }
      if (previous && previous.alert !== score.alert) {
        this.recordEvent("alert_changed", {
          from: previous.alert,
          to:   score.alert,
        });
      }
      if (score.anomalyFlag && (!previous || !previous.anomalyFlag)) {
        this.recordEvent("anomaly_detected", {
          score: score.score,
          successRate: score.successRate,
        });
      }
      if (score.source === "deactivated") {
        this.recordEvent("agent_deactivated", { score: score.score });
      }

      return score;
    } catch (err) {
      this.lastError = err as Error;
      this.recordEvent("refresh_failed", { error: String(err) });
      return null;
    }
  }

  recordEvent(type: string, data: Record<string, unknown>): void {
    const ev: TelemetryEvent = { type, timestamp: Date.now(), data };
    this.telemetry.push(ev);
    if (this.telemetry.length > this.maxTelemetry) {
      this.telemetry.shift();
    }
    if (this.config.enableTelemetry) {
      // eslint-disable-next-line no-console
      console.log(`[Helixor] ${type}`, data);
    }
  }

  getTelemetry(): readonly TelemetryEvent[] {
    return this.telemetry;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-runtime singleton registry
//
// elizaOS may run multiple agent characters in one process. Key state by
// runtime.agentId so each character has isolated state.
// ─────────────────────────────────────────────────────────────────────────────

const _states = new WeakMap<object, PluginState>();

export function getOrInitState(runtime: object, config: HelixorPluginConfig): PluginState {
  let s = _states.get(runtime);
  if (!s) {
    s = new PluginState(config);
    _states.set(runtime, s);
  }
  return s;
}

export function disposeState(runtime: object): void {
  const s = _states.get(runtime);
  if (s) {
    s.stopRefreshLoop();
    _states.delete(runtime);
  }
}

export function _resetForTests(): void {
  // WeakMap can't be cleared; tests must instantiate fresh runtimes
}
