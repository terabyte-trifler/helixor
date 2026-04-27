// =============================================================================
// tests/onchain.ts — read TrustCertificate state from chain.
//
// Day 7 cert layout (from helixor-programs/programs/health-oracle/src/state.rs):
//   8 bytes Anchor discriminator
//   32 bytes agent_wallet
//   2 bytes score (u16 LE)
//   1 byte alert (AlertLevel u8)
//   2 bytes success_rate
//   4 bytes tx_count_7d
//   1 byte anomaly_flag
//   8 bytes updated_at (i64 LE)
//   1 byte bump
//   16 bytes baseline_hash_prefix
//   1 byte scoring_algo_version
//   1 byte weights_version
//
// We don't decode the entire layout in this helper — just enough to verify
// the cert exists and the score matches what we expected.
// =============================================================================

import { Connection, PublicKey } from "@solana/web3.js";

import type { E2EEnv } from "./env";

export interface OnchainCert {
  pda:                 PublicKey;
  exists:              boolean;
  score:               number;
  alert:               "GREEN" | "YELLOW" | "RED";
  successRate:         number;       // basis points
  txCount7d:           number;
  anomalyFlag:         boolean;
  updatedAt:           number;
  scoringAlgoVersion:  number;
  weightsVersion:      number;
}

export function deriveTrustCertPda(env: E2EEnv, agentWallet: string): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("score"), new PublicKey(agentWallet).toBuffer()],
    env.programId,
  );
  return pda;
}

const ALERT_BY_BYTE: Record<number, "GREEN" | "YELLOW" | "RED"> = {
  0: "GREEN",
  1: "YELLOW",
  2: "RED",
  // Backward-compatible fallback if the enum is ever written with explicit repr values.
  3: "RED",
};

export async function readTrustCert(
  env:          E2EEnv,
  agentWallet:  string,
): Promise<OnchainCert | null> {
  const pda  = deriveTrustCertPda(env, agentWallet);
  const conn = new Connection(env.solanaRpcUrl, "confirmed");
  const info = await conn.getAccountInfo(pda);
  if (!info) {
    return { pda, exists: false } as OnchainCert;
  }

  const data = info.data;
  // After 8-byte Anchor discriminator
  let off = 8;

  const ownerWalletBytes = data.subarray(off, off + 32); off += 32;
  const score        = data.readUInt16LE(off); off += 2;
  const alertByte    = data.readUInt8(off);    off += 1;
  const successRate  = data.readUInt16LE(off); off += 2;
  const txCount7d    = data.readUInt32LE(off); off += 4;
  const anomalyByte  = data.readUInt8(off);    off += 1;
  const updatedAtRaw = data.readBigInt64LE(off); off += 8;
  /* skip 1 byte bump */                       off += 1;
  /* skip 16 bytes baseline_hash_prefix */     off += 16;
  const scoringAlgoV = data.readUInt8(off);    off += 1;
  const weightsV     = data.readUInt8(off);    off += 1;

  const alert = ALERT_BY_BYTE[alertByte] ?? "RED";
  void ownerWalletBytes;

  return {
    pda,
    exists: true,
    score,
    alert,
    successRate,
    txCount7d,
    anomalyFlag: anomalyByte === 1,
    updatedAt: Number(updatedAtRaw),
    scoringAlgoVersion: scoringAlgoV,
    weightsVersion:     weightsV,
  };
}
