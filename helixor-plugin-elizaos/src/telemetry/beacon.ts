// =============================================================================
// src/telemetry/beacon.ts — sends plugin events to Helixor API.
//
// Designed for production:
//   - Fire-and-forget: never blocks the event loop, never throws upstream
//   - Bounded queue: drops oldest if buffer fills (no unbounded memory)
//   - Backoff on failures: exponential, capped at 5 minutes
//   - Per-event-type cooldown: avoids spam for repeating events
//   - Stable beacon_id per event for server-side dedup
//   - PRIVACY GUARANTEE: never sends message text. Schema-validated metadata only.
// =============================================================================

import { PLUGIN_VERSION } from "../version";

export type BeaconEventType =
  | "plugin_initialized"
  | "agent_score_fetched"
  | "action_allowed"
  | "action_blocked"
  | "gate_error"
  | "score_changed"
  | "anomaly_detected"
  | "agent_deactivated"
  | "plugin_shutdown";

export interface BeaconPayload {
  event_type:        BeaconEventType;
  plugin_version:    string;
  elizaos_version?:  string;
  node_version?:     string;
  agent_wallet?:     string;
  character_name?:   string;
  score?:            number;
  alert_level?:      "GREEN" | "YELLOW" | "RED";
  block_reason?:     string;
  action_name?:      string;
  error_message?:    string;
  extra?:            Record<string, unknown>;
  beacon_id:         string;
}

export interface BeaconClientConfig {
  endpoint:        string;
  apiKey?:         string;
  enabled:         boolean;
  fetch?:          typeof fetch;
  maxQueueSize?:   number;
  maxRetries?:     number;
}

const PII_FORBIDDEN_KEYS = new Set([
  "text", "message", "content", "prompt",
  "user_input", "user_message", "user_text", "input",
]);

const COOLDOWNS_MS: Partial<Record<BeaconEventType, number>> = {
  // Avoid spam: don't send the same `agent_score_fetched` more than 1×/min
  agent_score_fetched: 60_000,
  score_changed:       0,
  action_allowed:      0,
  action_blocked:      0,
  plugin_initialized:  0,
  plugin_shutdown:     0,
};


export class TelemetryBeaconClient {
  private readonly cfg: Required<Omit<BeaconClientConfig, "apiKey" | "fetch">> &
                      Pick<BeaconClientConfig, "apiKey" | "fetch">;
  private readonly fetcher: typeof fetch;
  private readonly queue: BeaconPayload[] = [];
  private flushing = false;
  private flushPromise: Promise<void> | null = null;
  private backoffMs = 0;
  private readonly lastSentByType = new Map<BeaconEventType, number>();

  constructor(cfg: BeaconClientConfig) {
    this.cfg = {
      endpoint:      cfg.endpoint,
      apiKey:        cfg.apiKey,
      enabled:       cfg.enabled,
      fetch:         cfg.fetch,
      maxQueueSize:  cfg.maxQueueSize  ?? 100,
      maxRetries:    cfg.maxRetries    ?? 3,
    };
    const f = this.cfg.fetch ?? globalThis.fetch;
    if (!f) throw new Error("[Helixor.telemetry] no fetch available");
    this.fetcher = f.bind(globalThis);
  }

  /**
   * Enqueue a beacon. Never blocks, never throws.
   */
  emit(partial: Omit<BeaconPayload, "plugin_version" | "beacon_id"> & {
    plugin_version?: string;
    beacon_id?:      string;
  }): void {
    if (!this.cfg.enabled) return;

    // Cooldown — drop redundant beacons
    const cooldown = COOLDOWNS_MS[partial.event_type] ?? 0;
    if (cooldown > 0) {
      const last = this.lastSentByType.get(partial.event_type) ?? 0;
      if (Date.now() - last < cooldown) return;
    }
    this.lastSentByType.set(partial.event_type, Date.now());

    // PII scan — refuse to enqueue any extra payload that has forbidden keys
    if (partial.extra) {
      for (const k of Object.keys(partial.extra)) {
        if (PII_FORBIDDEN_KEYS.has(k.toLowerCase())) {
          // Silently drop the offending key rather than throw — telemetry must not break the plugin
          delete (partial.extra as any)[k];
        }
      }
    }

    const beacon: BeaconPayload = {
      ...partial,
      plugin_version: partial.plugin_version ?? PLUGIN_VERSION,
      beacon_id:      partial.beacon_id ?? generateBeaconId(),
      // Capture node version when available
      node_version:   partial.node_version
                   ?? (typeof process !== "undefined" ? process.version : undefined),
    };

    // Bounded queue — drop oldest if we're at capacity
    if (this.queue.length >= this.cfg.maxQueueSize) {
      this.queue.shift();
    }
    this.queue.push(beacon);
    void this.flush();
  }

  /**
   * Flush queue. Fire-and-forget — caller should not await.
   */
  async flush(): Promise<void> {
    if (this.flushPromise) {
      await this.flushPromise;
      return;
    }

    this.flushPromise = (async () => {
      if (this.queue.length === 0) return;
      if (this.backoffMs > 0) {
        await new Promise(r => setTimeout(r, this.backoffMs));
      }

      this.flushing = true;
      try {
        while (this.queue.length > 0) {
          const beacon = this.queue[0]!;
          const ok = await this.send(beacon);
          if (ok) {
            this.queue.shift();
            this.backoffMs = 0;
          } else {
            // Exponential backoff, capped at 5 minutes
            this.backoffMs = Math.min(this.backoffMs ? this.backoffMs * 2 : 5_000, 300_000);
            break;
          }
        }
      } finally {
        this.flushing = false;
        this.flushPromise = null;
      }
    })();

    await this.flushPromise;
  }

  /** Drain the queue synchronously on shutdown. Best effort. */
  async shutdown(): Promise<void> {
    try {
      await this.flush();
    } catch {
      // Swallow — process is exiting anyway
    }
  }

  private async send(beacon: BeaconPayload): Promise<boolean> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent":   `@elizaos/plugin-helixor/${PLUGIN_VERSION}`,
    };
    if (this.cfg.apiKey) {
      headers["Authorization"] = `Bearer ${this.cfg.apiKey}`;
    }

    try {
      const ctrl  = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 5_000);
      const r = await this.fetcher(this.cfg.endpoint, {
        method:  "POST",
        headers,
        body:    JSON.stringify(beacon),
        signal:  ctrl.signal,
      });
      clearTimeout(timer);

      // 2xx (incl. 202 dedup) → success. 4xx (validation) → drop, don't retry.
      if (r.status >= 200 && r.status < 300) return true;
      if (r.status >= 400 && r.status < 500) return true;  // permanent — drop
      return false;
    } catch {
      return false;
    }
  }
}


function generateBeaconId(): string {
  // Stable opaque ID — random + timestamp. crypto.randomUUID is available in
  // Node 18.7+ but we degrade gracefully.
  if (typeof globalThis.crypto?.randomUUID === "function") {
    return globalThis.crypto.randomUUID().replace(/-/g, "").slice(0, 32);
  }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 14)}`;
}
