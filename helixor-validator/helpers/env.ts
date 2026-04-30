// =============================================================================
// helpers/env.ts — env validation. Same mainnet-refusal as Day 10/13.
// =============================================================================

import { Connection, PublicKey } from "@solana/web3.js";
import os from "node:os";
import path from "node:path";

const REQUIRED = [
  "HELIXOR_API_URL",
  "HELIXOR_PROGRAM_ID",
  "DATABASE_URL",
  "SOLANA_RPC_URL",
] as const;

const FORBIDDEN_HOST_SUBSTRINGS = [
  "api.mainnet-beta.solana.com",
  "mainnet.helius-rpc.com",
  "mainnet.helius",
];


export interface ValidationEnv {
  apiUrl:           string;
  programId:        PublicKey;
  databaseUrl:      string;
  solanaRpcUrl:     string;
  oracleDir:        string;
  ownerKeypairPath: string;
  /** State directory for the validation run — JSON snapshots, reports. */
  stateDir:         string;
}

export class EnvError extends Error {
  constructor(msg: string) {
    super(`[helixor-validation] ${msg}`);
    this.name = "EnvError";
  }
}

export function loadEnv(): ValidationEnv {
  const missing = REQUIRED.filter(k => !process.env[k]);
  if (missing.length) {
    throw new EnvError(`Missing required env vars: ${missing.join(", ")}`);
  }

  const apiUrl = process.env.HELIXOR_API_URL!;
  const rpcUrl = process.env.SOLANA_RPC_URL!;

  for (const h of [apiUrl, rpcUrl]) {
    const lower = h.toLowerCase();
    for (const banned of FORBIDDEN_HOST_SUBSTRINGS) {
      if (lower.includes(banned)) {
        throw new EnvError(`Refusing to run validation against suspected mainnet endpoint '${h}'.`);
      }
    }
    if (lower.includes("mainnet")) {
      throw new EnvError(`Endpoint '${h}' contains 'mainnet'. Refusing.`);
    }
  }

  let programPk: PublicKey;
  try { programPk = new PublicKey(process.env.HELIXOR_PROGRAM_ID!); }
  catch { throw new EnvError(`HELIXOR_PROGRAM_ID is not valid base58.`); }

  return {
    apiUrl:       apiUrl.replace(/\/+$/, ""),
    programId:    programPk,
    databaseUrl:  process.env.DATABASE_URL!,
    solanaRpcUrl: rpcUrl,
    oracleDir:    process.env.HELIXOR_ORACLE_DIR ?? "../helixor-oracle",
    ownerKeypairPath: process.env.HELIXOR_VALIDATION_OWNER_KEYPAIR_PATH
      ?? path.join(os.homedir(), ".config", "solana", "id.json"),
    stateDir:     process.env.HELIXOR_VALIDATION_STATE_DIR ?? "./reports",
  };
}


export async function verifyConnectivity(env: ValidationEnv): Promise<void> {
  const conn = new Connection(env.solanaRpcUrl, "confirmed");
  const slot = await conn.getSlot();
  if (slot < 1) throw new EnvError(`RPC returned suspicious slot ${slot}`);

  const r = await fetch(`${env.apiUrl}/health`);
  if (!r.ok) throw new EnvError(`API /health returned ${r.status}`);

  const info = await conn.getAccountInfo(env.programId);
  if (!info) throw new EnvError(`Program ${env.programId.toBase58()} not deployed on this RPC.`);
}
