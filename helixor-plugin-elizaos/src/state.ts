// =============================================================================
// @elizaos/plugin-helixor — plugin state (Day 12 + VULN-12 extensions).
// Owns the TelemetryBeaconClient lifecycle and the VULN-12 last-known-good
// ScoreCache.
// =============================================================================

import { HelixorClient, type TrustScore } from "@helixor/client";

import type { HelixorPluginConfig } from "./config";
import { ScoreCache } from "./score_cache";
import { TelemetryBeaconClient } from "./telemetry/beacon";


interface TelemetryEvent {
  type:      string;
  timestamp: number;
  data:      Record<string, unknown>;
}


export class PluginState {
  public readonly client:     HelixorClient;
  public readonly beacon:     TelemetryBeaconClient;
  public readonly config:     HelixorPluginConfig;
  // VULN-12: the last-known-good cache. Read by the trust_gate's fail-closed
  // branch; written by every successful score fetch via `recordScore`.
  public readonly scoreCache: ScoreCache;

  public lastScore:        TrustScore | null = null;
  public lastScoreFetchedAt = 0;
  public lastError:        Error | null = null;

  private readonly localTelemetry: TelemetryEvent[] = [];
  private readonly maxTelemetry = 100;

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
    this.beacon = new TelemetryBeaconClient({
      endpoint: config.telemetryEndpoint,
      apiKey:   config.apiKey,
      enabled:  config.telemetryEnabled,
    });
    this.scoreCache = new ScoreCache(config.cacheTtlMs);
  }

  /**
   * Centralized write of a successfully-fetched score. Keeps the legacy
   * `lastScore` / `lastScoreFetchedAt` fields and the VULN-12 ScoreCache
   * in lock-step so the fail-closed-with-cache path always sees the latest
   * known-good entry, regardless of which call site fetched it.
   */
  recordScore(score: TrustScore, now: number = Date.now()): void {
    this.lastScore = score;
    this.lastScoreFetchedAt = now;
    this.scoreCache.put(score, now);
  }

  startRefreshLoop(): void {
    if (this.refreshTimer) return;
    this.refreshTimer = setInterval(() => {
      this.refreshScore().catch((err) => {
        this.recordEvent("refresh_failed", { error: String(err) });
      });
    }, this.config.refreshIntervalMs);
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
      this.client.invalidate(this.config.agentWallet);
      const score = await this.client.getScore(this.config.agentWallet);
      const previous = this.lastScore;

      this.recordScore(score);
      this.lastError = null;

      // Local telemetry
      if (previous && previous.score !== score.score) {
        this.recordEvent("score_changed", {
          from: previous.score, to: score.score, delta: score.score - previous.score,
        });
        this.beacon.emit({
          event_type:    "score_changed",
          agent_wallet:  this.config.agentWallet,
          score:         score.score,
          alert_level:   score.alert,
          extra: { from: previous.score, to: score.score },
        });
      }
      if (score.anomalyFlag && (!previous || !previous.anomalyFlag)) {
        this.recordEvent("anomaly_detected", { score: score.score });
        this.beacon.emit({
          event_type:    "anomaly_detected",
          agent_wallet:  this.config.agentWallet,
          score:         score.score,
          alert_level:   score.alert,
        });
      }
      if (score.source === "deactivated") {
        this.recordEvent("agent_deactivated", { score: score.score });
        this.beacon.emit({
          event_type:    "agent_deactivated",
          agent_wallet:  this.config.agentWallet,
          score:         score.score,
        });
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
    this.localTelemetry.push(ev);
    if (this.localTelemetry.length > this.maxTelemetry) {
      this.localTelemetry.shift();
    }
    if (this.config.enableTelemetry) {
      // eslint-disable-next-line no-console
      console.log(`[Helixor] ${type}`, data);
    }
  }

  getTelemetry(): readonly TelemetryEvent[] {
    return this.localTelemetry;
  }
}


// Per-runtime singleton registry
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
    void s.beacon.shutdown();
    _states.delete(runtime);
  }
}
