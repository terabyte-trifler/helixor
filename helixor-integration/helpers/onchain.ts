// =============================================================================
// helpers/onchain.ts — read TrustCertificate + AgentRegistration + OracleConfig.
// =============================================================================

import { Connection, PublicKey } from "@solana/web3.js";

import type { IntegrationEnv } from "./env";


// ─────────────────────────────────────────────────────────────────────────────
// TrustCertificate
// ─────────────────────────────────────────────────────────────────────────────

export interface OnchainCert {
  pda:                PublicKey;
  exists:             boolean;
  score?:             number;
  alert?:             "GREEN" | "YELLOW" | "RED";
  successRate?:       number;
  txCount7d?:         number;
  anomalyFlag?:       boolean;
  updatedAt?:         number;
  scoringAlgoVersion?: number;
  weightsVersion?:    number;
}

const ALERT_BY_BYTE: Record<number, "GREEN" | "YELLOW" | "RED"> = {
  // Anchor/Borsh encodes enum variants by ordinal index, so Green/Yellow/Red
  // land on 0/1/2 even though the Rust enum also declares repr(u8).
  0: "GREEN", 1: "YELLOW", 2: "RED",
  // Accept the explicit repr values too so the helper stays tolerant if the
  // program later switches to manual byte encoding.
  3: "RED",
};

export function deriveTrustCertPda(env: IntegrationEnv, wallet: string): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("score"), new PublicKey(wallet).toBuffer()],
    env.programId,
  );
  return pda;
}

export async function readTrustCert(
  env:    IntegrationEnv,
  wallet: string,
): Promise<OnchainCert> {
  const pda  = deriveTrustCertPda(env, wallet);
  const conn = new Connection(env.solanaRpcUrl, "confirmed");
  const info = await conn.getAccountInfo(pda);
  if (!info) return { pda, exists: false };

  const data = info.data;
  let off = 8;                                      // skip Anchor discriminator
  /* skip 32-byte agent pubkey */ off += 32;
  const score        = data.readUInt16LE(off); off += 2;
  const alertByte    = data.readUInt8(off);    off += 1;
  const successRate  = data.readUInt16LE(off); off += 2;
  const txCount7d    = data.readUInt32LE(off); off += 4;
  const anomalyByte  = data.readUInt8(off);    off += 1;
  const updatedAtRaw = data.readBigInt64LE(off); off += 8;
  /* skip 1-byte bump */                         off += 1;
  /* skip 16-byte baseline_hash_prefix */        off += 16;
  const scoringV     = data.readUInt8(off);    off += 1;
  const weightsV     = data.readUInt8(off);    off += 1;

  return {
    pda, exists: true,
    score, alert: ALERT_BY_BYTE[alertByte] ?? "RED",
    successRate, txCount7d,
    anomalyFlag: anomalyByte === 1,
    updatedAt: Number(updatedAtRaw),
    scoringAlgoVersion: scoringV,
    weightsVersion:     weightsV,
  };
}


// ─────────────────────────────────────────────────────────────────────────────
// AgentRegistration
// ─────────────────────────────────────────────────────────────────────────────

export function deriveAgentRegistrationPda(env: IntegrationEnv, wallet: string): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("agent"), new PublicKey(wallet).toBuffer()],
    env.programId,
  );
  return pda;
}

export async function readAgentRegistration(
  env:    IntegrationEnv,
  wallet: string,
): Promise<{ pda: PublicKey; exists: boolean; rawDataLength?: number }> {
  const pda  = deriveAgentRegistrationPda(env, wallet);
  const conn = new Connection(env.solanaRpcUrl, "confirmed");
  const info = await conn.getAccountInfo(pda);
  return {
    pda, exists: !!info,
    rawDataLength: info?.data.length,
  };
}


// ─────────────────────────────────────────────────────────────────────────────
// OracleConfig
// ─────────────────────────────────────────────────────────────────────────────

export function deriveOracleConfigPda(env: IntegrationEnv): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("oracle_config")],
    env.programId,
  );
  return pda;
}

export async function readOracleConfig(env: IntegrationEnv): Promise<{
  exists:   boolean;
  rawData?: Buffer;
}> {
  const pda  = deriveOracleConfigPda(env);
  const conn = new Connection(env.solanaRpcUrl, "confirmed");
  const info = await conn.getAccountInfo(pda);
  return { exists: !!info, rawData: info?.data };
}
