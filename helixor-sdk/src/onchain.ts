import { Connection, PublicKey } from "@solana/web3.js";

import { decodeEpochState, decodeHealthCertificate } from "./decode";
import { certificatePda, epochStatePda } from "./pdas";
import {
  alertTierFromCode,
  type EpochScore,
  type HealthScore,
  type HelixorProgramIds,
} from "./types";

export class CertificateNotFoundError extends Error {
  constructor(agent: PublicKey, epoch: number) {
    super(`no HealthCertificate for agent ${agent.toBase58()} at epoch ${epoch}`);
    this.name = "CertificateNotFoundError";
  }
}

export class OnChainHelixorClient {
  constructor(
    private readonly connection: Connection,
    private readonly programs: HelixorProgramIds,
  ) {}

  async getCurrentEpoch(): Promise<number> {
    const info = await this.connection.getAccountInfo(epochStatePda(this.programs.healthOracle));
    if (!info) {
      throw new Error("EpochState is not initialized");
    }
    return decodeEpochState(info.data).currentEpoch;
  }

  async getScore(agent: PublicKey): Promise<HealthScore> {
    const currentEpoch = await this.getCurrentEpoch();
    const epochScore = await this.getScoreAtEpoch(agent, currentEpoch);
    return {
      agent: epochScore.agent,
      score: epochScore.score,
      alert: epochScore.alert,
      flags: epochScore.flags,
      issuedAt: epochScore.issuedAt,
    };
  }

  async getScoreAtEpoch(agent: PublicKey, epoch: number): Promise<EpochScore> {
    const certPda = certificatePda(this.programs.certificateIssuer, agent, epoch);
    const info = await this.connection.getAccountInfo(certPda);
    if (!info) {
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

  async getScoreHistory(
    agent: PublicKey,
    fromEpoch: number,
    toEpoch: number,
  ): Promise<EpochScore[]> {
    if (toEpoch < fromEpoch) {
      throw new Error(`toEpoch (${toEpoch}) is before fromEpoch (${fromEpoch})`);
    }

    const pdas: PublicKey[] = [];
    for (let epoch = fromEpoch; epoch <= toEpoch; epoch++) {
      pdas.push(certificatePda(this.programs.certificateIssuer, agent, epoch));
    }

    const infos = await this.connection.getMultipleAccountsInfo(pdas);
    return infos.flatMap((info, index) => {
      if (!info) return [];
      const cert = decodeHealthCertificate(info.data);
      return [{
        agent,
        epoch: cert.epoch,
        score: cert.score,
        alert: alertTierFromCode(cert.alertTier),
        flags: cert.flags,
        issuedAt: cert.issuedAt,
        confidence: cert.confidence,
        immediateRed: cert.immediateRed,
      }];
    });
  }
}
