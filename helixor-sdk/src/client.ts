// =============================================================================
// helixor-sdk/src/client.ts — the Helixor SDK client.
//
// `HelixorClient.getScore(agent)` is the MVP-compatible entry point. In the
// MVP it read a single score account; in V2 it reads the agent's
// current-epoch HealthCertificate from the certificate-issuer program. The
// RETURN SHAPE is unchanged (`HealthScore`), so MVP consumers are unaffected.
//
// The V2 additions are purely additive:
//   getScoreAtEpoch(agent, epoch) — any historical epoch's score
//   getScoreHistory(agent, from, to) — a range of epochs
//   getCurrentEpoch() — the live epoch number
//
// READING STRATEGY
// ----------------
// A certificate is a plain account. The SDK reads it with a direct RPC
// `getAccountInfo` and decodes the fixed byte layout — no transaction, no
// fee. (The on-chain get_health / get_certificate instructions exist for
// CPI callers; an SDK does not need them.)
// =============================================================================

import { Connection, PublicKey } from "@solana/web3.js";

import {
  AgentNotFoundError,
  AgentDeactivatedError,
  AnomalyDetectedError,
  HelixorError,
  InvalidAgentWalletError,
  NetworkError,
  ProvisionalScoreError,
  RateLimitedError,
  ScoreTooLowError,
  ServerError,
  StaleScoreError,
  TimeoutError,
} from "./errors";
import {
  AlertTier,
  alertTierFromCode,
  EpochScore,
  HealthScore,
  HelixorProgramIds,
  TrustScore,
} from "./types";
import {
  certificatePda,
  epochStatePda,
} from "./pdas";
import {
  decodeEpochState,
  decodeHealthCertificate,
} from "./decode";

export class CertificateNotFoundError extends Error {
  constructor(agent: PublicKey, epoch: number) {
    super(`no HealthCertificate for agent ${agent.toBase58()} at epoch ${epoch}`);
    this.name = "CertificateNotFoundError";
  }
}

export interface HelixorApiClientOptions {
  apiBase: string;
  apiKey?: string;
  timeoutMs?: number;
  maxRetries?: number;
  cacheTtlMs?: number;
}

export class HelixorClient {
  private readonly apiBase?: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;
  private readonly cacheTtlMs: number = 0;
  private readonly cache = new Map<string, { expiresAt: number; score: TrustScore }>();

  constructor(
    connectionOrOptions: Connection | HelixorApiClientOptions,
    private readonly programs?: HelixorProgramIds
  ) {
    if (connectionOrOptions instanceof Connection) {
      this.connection = connectionOrOptions;
      this.timeoutMs = 10_000;
      return;
    }
    this.apiBase = connectionOrOptions.apiBase.replace(/\/+$/, "");
    this.apiKey = connectionOrOptions.apiKey;
    this.timeoutMs = connectionOrOptions.timeoutMs ?? 10_000;
    this.cacheTtlMs = connectionOrOptions.cacheTtlMs ?? 0;
    this.connection = undefined as unknown as Connection;
  }

  private readonly connection: Connection;

  // ===========================================================================
  // getScore — the MVP-compatible entry point
  // ===========================================================================

  /**
   * The agent's CURRENT trust score.
   *
   * MVP-COMPATIBLE: returns the frozen `HealthScore` shape. The MVP read a
   * single overwritten account; V2 reads the current-epoch HealthCertificate.
   * A consumer written against the MVP `getScore` keeps working unchanged.
   *
   * Throws `CertificateNotFoundError` if the agent has no certificate for
   * the current epoch yet (e.g. scoring has not run this cycle).
   */
  async getScore(agent: string): Promise<TrustScore>;
  async getScore(agent: PublicKey): Promise<HealthScore>;
  async getScore(agent: PublicKey | string): Promise<HealthScore | TrustScore> {
    if (this.apiBase) {
      return this.getScoreFromApi(String(agent));
    }
    if (!this.programs) {
      throw new Error("program IDs required for on-chain HelixorClient mode");
    }
    const agentKey = typeof agent === "string" ? new PublicKey(agent) : agent;
    const epoch = await this.getCurrentEpoch();
    const full = await this.getScoreAtEpoch(agentKey, epoch);
    // Project the EpochScore down to the frozen HealthScore shape — the
    // epoch / immediateRed fields are V2 additions not in the MVP contract.
    return {
      agent: full.agent,
      score: full.score,
      alert: full.alert,
      flags: full.flags,
      issuedAt: full.issuedAt,
    };
  }

  // ===========================================================================
  // V2 additions — epoch history (additive, never breaking)
  // ===========================================================================

  /** The current epoch number, from the health-oracle EpochState. */
  async getCurrentEpoch(): Promise<number> {
    if (!this.programs) {
      throw new Error("program IDs required for on-chain HelixorClient mode");
    }
    const pda = epochStatePda(this.programs.healthOracle);
    const info = await this.connection.getAccountInfo(pda);
    if (info === null) {
      throw new Error("EpochState not initialised — run initialize_epoch");
    }
    return decodeEpochState(info.data).currentEpoch;
  }

  async requireMinScore(
    agent: string,
    minimum: number,
    opts: { allowStale?: boolean; allowAnomaly?: boolean; allowProvisional?: boolean } = {},
  ): Promise<TrustScore> {
    const score = await this.getScoreFromApi(agent);
    if (score.source === "deactivated") {
      throw new AgentDeactivatedError(score);
    }
    if (score.source === "provisional" && !opts.allowProvisional) {
      throw new ProvisionalScoreError(score);
    }
    if (!score.isFresh && !opts.allowStale) {
      throw new StaleScoreError(score);
    }
    if (score.anomalyFlag && !opts.allowAnomaly) {
      throw new AnomalyDetectedError(score);
    }
    if (score.score < minimum) {
      throw new ScoreTooLowError(score, minimum);
    }
    return score;
  }

  invalidate(agent?: string): void {
    if (agent) {
      this.cache.delete(agent);
      return;
    }
    this.cache.clear();
  }

  private async getScoreFromApi(agent: string): Promise<TrustScore> {
    try {
      new PublicKey(agent);
    } catch {
      throw new InvalidAgentWalletError(agent);
    }
    const cached = this.cache.get(agent);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.score;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let res: Response;
    try {
      res = await fetch(`${this.apiBase}/score/${agent}`, {
        signal: controller.signal,
        headers: this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : undefined,
      });
    } catch (err) {
      if ((err as Error).name === "AbortError") {
        throw new TimeoutError(this.timeoutMs);
      }
      throw new NetworkError((err as Error).message);
    } finally {
      clearTimeout(timer);
    }

    const requestId = res.headers.get("x-request-id") ?? undefined;
    const body: any = await res.json().catch(() => ({}));
    if (res.status === 404 || body.code === "AGENT_NOT_FOUND") {
      throw new AgentNotFoundError(agent, requestId);
    }
    if (res.status === 429) {
      throw new RateLimitedError();
    }
    if (!res.ok) {
      throw new ServerError(res.status, body.error ?? res.statusText, requestId);
    }
    const score = mapApiScore(body);
    if (this.cacheTtlMs > 0) {
      this.cache.set(agent, { expiresAt: Date.now() + this.cacheTtlMs, score });
    }
    return score;
  }

  /**
   * The agent's score for a SPECIFIC epoch. Because V2 keeps a per-epoch
   * certificate, any past epoch is queryable — this is the on-chain history.
   */
  async getScoreAtEpoch(agent: PublicKey, epoch: number): Promise<EpochScore> {
    if (!this.programs) {
      throw new Error("program IDs required for on-chain HelixorClient mode");
    }
    const pda = certificatePda(
      this.programs.certificateIssuer,
      agent,
      epoch
    );
    const info = await this.connection.getAccountInfo(pda);
    if (info === null) {
      throw new CertificateNotFoundError(agent, epoch);
    }
    const cert = decodeHealthCertificate(info.data);
    return {
      agent,
      epoch: cert.epoch,
      score: cert.score,
      alert: alertTierFromCode(cert.alertTier),
      flags: cert.flags,
      issuedAt: cert.issuedAt,
      immediateRed: cert.immediateRed,
    };
  }

  /**
   * Every score for an agent across an inclusive epoch range. Epochs with
   * no certificate are simply omitted — the result is sparse, not padded.
   *
   * This is the V2 capability the MVP could not offer: the MVP overwrote
   * its single certificate, so history did not exist.
   */
  async getScoreHistory(
    agent: PublicKey,
    fromEpoch: number,
    toEpoch: number
  ): Promise<EpochScore[]> {
    if (!this.programs) {
      throw new Error("program IDs required for on-chain HelixorClient mode");
    }
    if (toEpoch < fromEpoch) {
      throw new Error(`toEpoch (${toEpoch}) is before fromEpoch (${fromEpoch})`);
    }
    const pdas: PublicKey[] = [];
    for (let e = fromEpoch; e <= toEpoch; e++) {
      pdas.push(
        certificatePda(this.programs.certificateIssuer, agent, e)
      );
    }
    // One batched RPC for the whole range.
    const infos = await this.connection.getMultipleAccountsInfo(pdas);

    const out: EpochScore[] = [];
    infos.forEach((info, i) => {
      if (info === null) return; // no certificate for this epoch — skip
      const cert = decodeHealthCertificate(info.data);
      out.push({
        agent,
        epoch: cert.epoch,
        score: cert.score,
        alert: alertTierFromCode(cert.alertTier),
        flags: cert.flags,
        issuedAt: cert.issuedAt,
        immediateRed: cert.immediateRed,
      });
    });
    return out;
  }
}

function mapApiScore(body: any): TrustScore {
  return {
    agentWallet: body.agent_wallet,
    score: body.score,
    alert: body.alert,
    source: body.source,
    successRate: body.success_rate,
    anomalyFlag: body.anomaly_flag,
    updatedAt: body.updated_at,
    isFresh: body.is_fresh,
    breakdown: body.breakdown ? {
      successRateScore: body.breakdown.success_rate_score,
      consistencyScore: body.breakdown.consistency_score,
      stabilityScore: body.breakdown.stability_score,
      rawScore: body.breakdown.raw_score,
    } : null,
    scoringAlgoVersion: body.scoring_algo_version,
    weightsVersion: body.weights_version,
    baselineHashPrefix: body.baseline_hash_prefix,
  };
}
