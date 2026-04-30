// =============================================================================
// helpers/env.ts — environment validation for integration tests.
// Same mainnet-refusal pattern as Day 10 — these tests can mutate state.
// =============================================================================

import { Connection, PublicKey } from "@solana/web3.js";

const REQUIRED = [
  "HELIXOR_API_URL",
  "HELIXOR_PROGRAM_ID",
  "DATABASE_URL",
  "SOLANA_RPC_URL",
  "ORACLE_KEYPAIR_PATH",
] as const;

const FORBIDDEN_HOST_SUBSTRINGS = [
  "api.mainnet-beta.solana.com",
  "mainnet.helius-rpc.com",
  "mainnet.helius",
];

export interface IntegrationEnv {
  apiUrl:              string;
  programId:           PublicKey;
  databaseUrl:         string;
  solanaRpcUrl:        string;
  oracleKeypairPath:   string;
  oracleDir:           string;
  // optional knobs
  skipOnchainTests:    boolean;
  skipFailureTests:    boolean;
}

export class EnvError extends Error {
  constructor(msg: string) {
    super(`[helixor-integration] ${msg}`);
    this.name = "EnvError";
  }
}

export function loadEnv(): IntegrationEnv {
  const missing = REQUIRED.filter(k => !process.env[k]);
  if (missing.length) {
    throw new EnvError(
      `Missing required env vars: ${missing.join(", ")}. ` +
      `Copy .env.example to .env and fill in.`,
    );
  }

  const apiUrl    = process.env.HELIXOR_API_URL!;
  const rpcUrl    = process.env.SOLANA_RPC_URL!;
  const programId = process.env.HELIXOR_PROGRAM_ID!;

  for (const h of [apiUrl, rpcUrl]) {
    const lower = h.toLowerCase();
    for (const banned of FORBIDDEN_HOST_SUBSTRINGS) {
      if (lower.includes(banned)) {
        throw new EnvError(`Refusing to run integration tests against suspected mainnet endpoint '${h}'.`);
      }
    }
    if (lower.includes("mainnet")) {
      throw new EnvError(`Endpoint '${h}' contains 'mainnet'. Refusing.`);
    }
  }

  let programPk: PublicKey;
  try { programPk = new PublicKey(programId); }
  catch { throw new EnvError(`HELIXOR_PROGRAM_ID is not a valid base58 pubkey: ${programId}`); }

  return {
    apiUrl:            apiUrl.replace(/\/+$/, ""),
    programId:         programPk,
    databaseUrl:       process.env.DATABASE_URL!,
    solanaRpcUrl:      rpcUrl,
    oracleKeypairPath: process.env.ORACLE_KEYPAIR_PATH!,
    oracleDir:         process.env.HELIXOR_ORACLE_DIR ?? "../helixor-oracle",
    skipOnchainTests:  process.env.HELIXOR_SKIP_ONCHAIN  === "1",
    skipFailureTests:  process.env.HELIXOR_SKIP_FAILURE  === "1",
  };
}

export async function verifyConnectivity(env: IntegrationEnv): Promise<void> {
  const conn = new Connection(env.solanaRpcUrl, "confirmed");
  const slot = await conn.getSlot();
  if (slot < 1) throw new EnvError(`RPC returned suspicious slot ${slot}`);

  const res = await fetch(`${env.apiUrl}/health`);
  if (!res.ok) throw new EnvError(`API /health returned ${res.status}`);

  const info = await conn.getAccountInfo(env.programId);
  if (!info) throw new EnvError(`Program ${env.programId.toBase58()} not deployed on this RPC.`);
}
