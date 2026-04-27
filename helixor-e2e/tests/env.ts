// =============================================================================
// tests/env.ts — environment validation for E2E.
//
// Validates ALL env vars at import time. If anything is missing or pointing
// at production, refuse to run. There is no path where these tests touch
// mainnet.
// =============================================================================

import { Connection, PublicKey } from "@solana/web3.js";
import fs from "node:fs";
import path from "node:path";

const ENV_FILE = path.resolve(process.cwd(), ".env");

function loadDotEnvFile(): void {
  if (!fs.existsSync(ENV_FILE)) return;

  const content = fs.readFileSync(ENV_FILE, "utf-8");
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const eq = line.indexOf("=");
    if (eq === -1) continue;

    const key = line.slice(0, eq).trim();
    if (!key || process.env[key] !== undefined) continue;

    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}

loadDotEnvFile();

const REQUIRED = [
  "HELIXOR_API_URL",
  "HELIXOR_PROGRAM_ID",
  "DATABASE_URL",
  "SOLANA_RPC_URL",
  "ORACLE_KEYPAIR_PATH",
] as const;

// Hardcoded mainnet host suffixes — refuse if any of these appear
const FORBIDDEN_HOST_SUBSTRINGS = [
  "api.mainnet-beta.solana.com",
  "mainnet.helius-rpc.com",
  "mainnet.helius",
  "rpc.helius-rpc.com/?api-key",  // can be either; check explicit "mainnet" below
];

// Hardcoded mainnet program ID is unknown until deploy, but the devnet
// program ID is stable. Refuse to run if HELIXOR_PROGRAM_ID matches a
// known mainnet ID (set this once mainnet deploys).
const FORBIDDEN_PROGRAM_IDS: string[] = [
  // "MAINNET_PROGRAM_ID_HERE_AFTER_LAUNCH",
];

export interface E2EEnv {
  apiUrl:           string;
  programId:        PublicKey;
  databaseUrl:      string;
  solanaRpcUrl:     string;
  oracleKeypairPath: string;

  // Optional fixtures — populated by scripts/seed_loop_state.ts on first run
  testStableAgent:    string | null;
  testFailingAgent:   string | null;
  testProvisionalAgent: string | null;
  testOwnerWallet:    string | null;

  // For the optional CPI test
  consumerProgramId:  PublicKey | null;
}

class EnvError extends Error {
  constructor(msg: string) {
    super(`[helixor-e2e] ${msg}`);
    this.name = "EnvError";
  }
}

export function loadEnv(): E2EEnv {
  // Required vars
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

  // ── Mainnet refusal ──────────────────────────────────────────────────────
  const allHosts = [apiUrl, rpcUrl];
  for (const h of allHosts) {
    const lower = h.toLowerCase();
    for (const banned of FORBIDDEN_HOST_SUBSTRINGS) {
      if (lower.includes(banned)) {
        throw new EnvError(
          `Refusing to run E2E tests against suspected mainnet endpoint '${h}'. ` +
          `Use devnet or localnet only.`,
        );
      }
    }
    // Explicit "mainnet" in URL is enough cause for refusal
    if (lower.includes("mainnet")) {
      throw new EnvError(`Endpoint '${h}' contains 'mainnet'. Refusing.`);
    }
  }

  if (FORBIDDEN_PROGRAM_IDS.includes(programId)) {
    throw new EnvError(
      `HELIXOR_PROGRAM_ID is the mainnet program. E2E tests must run on devnet/localnet.`,
    );
  }

  // ── Validate program ID parses ────────────────────────────────────────────
  let programPk: PublicKey;
  try {
    programPk = new PublicKey(programId);
  } catch {
    throw new EnvError(`HELIXOR_PROGRAM_ID is not a valid base58 pubkey: ${programId}`);
  }

  let consumerProgramPk: PublicKey | null = null;
  if (process.env.HELIXOR_CONSUMER_PROGRAM_ID) {
    try {
      consumerProgramPk = new PublicKey(process.env.HELIXOR_CONSUMER_PROGRAM_ID);
    } catch {
      throw new EnvError(`HELIXOR_CONSUMER_PROGRAM_ID is not a valid base58 pubkey.`);
    }
  }

  return {
    apiUrl:            apiUrl.replace(/\/+$/, ""),
    programId:         programPk,
    databaseUrl:       process.env.DATABASE_URL!,
    solanaRpcUrl:      rpcUrl,
    oracleKeypairPath: process.env.ORACLE_KEYPAIR_PATH!,
    testStableAgent:     process.env.TEST_STABLE_AGENT_WALLET    || null,
    testFailingAgent:    process.env.TEST_FAILING_AGENT_WALLET   || null,
    testProvisionalAgent: process.env.TEST_PROVISIONAL_AGENT_WALLET || null,
    testOwnerWallet:     process.env.TEST_OWNER_WALLET           || null,
    consumerProgramId:   consumerProgramPk,
  };
}

/** One-shot RPC connectivity check — runs once at suite startup. */
export async function verifyConnectivity(env: E2EEnv): Promise<void> {
  const conn = new Connection(env.solanaRpcUrl, "confirmed");
  const slot = await conn.getSlot();
  if (slot < 1) throw new EnvError(`RPC returned suspicious slot ${slot}`);

  const res = await fetch(`${env.apiUrl}/health`);
  if (!res.ok) throw new EnvError(`API /health returned ${res.status}`);

  // Verify program is deployed
  const info = await conn.getAccountInfo(env.programId);
  if (!info) throw new EnvError(
    `Program ${env.programId.toBase58()} not found on ${env.solanaRpcUrl}. Is it deployed?`,
  );
}
