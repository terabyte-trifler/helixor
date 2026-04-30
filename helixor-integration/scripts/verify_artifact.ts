#!/usr/bin/env tsx
// =============================================================================
// scripts/verify_artifact.ts — verify deployed program matches the local build.
//
// Why: the spec doesn't ship this. Day 14 (mainnet) needs proof that the
// program at HELIXOR_PROGRAM_ID byte-matches the .so artifact we built and
// tested. Otherwise we have no idea what we deployed.
//
// Workflow:
//   1. Build: anchor build (in helixor-programs)
//   2. Deploy: anchor deploy (writes program at PROGRAM_ID)
//   3. Run this: dumps deployed bytes from chain, compares hash to local .so
//
// If they match → green light.
// If they don't → someone deployed a different artifact than we built.
// =============================================================================

import { Connection, PublicKey } from "@solana/web3.js";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import { loadEnv } from "../helpers/env";


function sha256(data: Uint8Array): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}


async function main() {
  const env = loadEnv();

  const programsDir = process.env.HELIXOR_PROGRAMS_DIR ?? "../helixor-programs";
  const localSoPath = path.join(programsDir, "target", "deploy", "health_oracle.so");

  console.log("");
  console.log("╔════════════════════════════════════════════════════════════╗");
  console.log("║  Helixor — Artifact Verification                          ║");
  console.log(`║  Program: ${env.programId.toBase58().padEnd(48)}║`);
  console.log(`║  RPC:     ${env.solanaRpcUrl.padEnd(48)}║`);
  console.log("╚════════════════════════════════════════════════════════════╝");
  console.log("");

  // Local artifact
  process.stdout.write("  • reading local .so ............ ");
  let localBytes: Uint8Array;
  try {
    localBytes = await fs.readFile(localSoPath);
    console.log(`\x1b[32m✓\x1b[0m  ${localBytes.length} bytes`);
  } catch (e: any) {
    console.log(`\x1b[31m✗\x1b[0m  ${e.message}`);
    console.log("    Run `anchor build` in helixor-programs first.");
    process.exit(1);
  }
  const localHash = sha256(localBytes);
  console.log(`      sha256: ${localHash}`);

  // On-chain: program account points to a programdata account (BPF Loader Upgradeable)
  process.stdout.write("\n  • fetching deployed program ..... ");
  const conn = new Connection(env.solanaRpcUrl, "confirmed");
  const programAccount = await conn.getAccountInfo(env.programId);
  if (!programAccount) {
    console.log(`\x1b[31m✗\x1b[0m  program account not found at ${env.programId.toBase58()}`);
    process.exit(1);
  }
  console.log(`\x1b[32m✓\x1b[0m  owner=${programAccount.owner.toBase58().slice(0, 12)}...`);

  // BPF Loader Upgradeable program account points to a "ProgramData" account
  // First 4 bytes after discriminator are little-endian variant index, then 32 bytes pubkey
  const programDataAddr = new PublicKey(programAccount.data.subarray(4, 36));

  process.stdout.write("  • fetching program-data ......... ");
  const programData = await conn.getAccountInfo(programDataAddr);
  if (!programData) {
    console.log(`\x1b[31m✗\x1b[0m  program-data account ${programDataAddr.toBase58()} not found`);
    process.exit(1);
  }
  console.log(`\x1b[32m✓\x1b[0m  ${programData.data.length} bytes raw`);

  // Strip the 45-byte ProgramData header (LoaderState::ProgramData discriminator + slot + upgrade authority)
  // Layout: 4 bytes variant + 8 bytes slot + 1 byte option tag + 32 bytes optional authority
  const HEADER_LEN = 45;
  const onchainBytes = programData.data.subarray(HEADER_LEN);
  console.log(`      stripped header → ${onchainBytes.length} bytes`);

  const onchainHash = sha256(onchainBytes);
  console.log(`      sha256: ${onchainHash}`);

  // Compare
  console.log("");
  if (onchainHash === localHash) {
    console.log("\x1b[32m✓ DEPLOYED ARTIFACT MATCHES LOCAL BUILD\x1b[0m");
    console.log("  Safe to point production at this program.");
    process.exit(0);
  }

  console.log("\x1b[31m✗ DEPLOYED ARTIFACT DOES NOT MATCH LOCAL BUILD\x1b[0m");
  console.log(`  local:    ${localHash}`);
  console.log(`  on-chain: ${onchainHash}`);
  console.log("");
  console.log("  This means the on-chain program was deployed from different source.");
  console.log("  Possible causes:");
  console.log("    1. Someone deployed a different commit");
  console.log("    2. Local build is stale (rerun `anchor build`)");
  console.log("    3. Compiler/toolchain version drift");
  console.log("");
  console.log("  Do NOT proceed to mainnet until these match.");
  process.exit(1);
}


main().catch((err) => { console.error(err); process.exit(1); });
