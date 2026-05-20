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
  AlertTier,
  alertTierFromCode,
  EpochScore,
  HealthScore,
  HelixorProgramIds,
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

export class HelixorClient {
  constructor(
    private readonly connection: Connection,
    private readonly programs: HelixorProgramIds
  ) {}

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
  async getScore(agent: PublicKey): Promise<HealthScore> {
    const epoch = await this.getCurrentEpoch();
    const full = await this.getScoreAtEpoch(agent, epoch);
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
    const pda = epochStatePda(this.programs.healthOracle);
    const info = await this.connection.getAccountInfo(pda);
    if (info === null) {
      throw new Error("EpochState not initialised — run initialize_epoch");
    }
    return decodeEpochState(info.data).currentEpoch;
  }

  /**
   * The agent's score for a SPECIFIC epoch. Because V2 keeps a per-epoch
   * certificate, any past epoch is queryable — this is the on-chain history.
   */
  async getScoreAtEpoch(agent: PublicKey, epoch: number): Promise<EpochScore> {
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
      confidence: cert.confidence,
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
        confidence: cert.confidence,
        immediateRed: cert.immediateRed,
      });
    });
    return out;
  }
}
