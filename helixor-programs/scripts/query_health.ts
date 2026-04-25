#!/usr/bin/env ts-node
// =============================================================================
// scripts/query_health.ts
//
// Manual Day 3 verification: query an agent's health from the CLI.
//
// Usage:
//   ts-node scripts/query_health.ts <agent-wallet-pubkey>
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair } from "@solana/web3.js";

const agentArg = process.argv[2];
if (!agentArg) {
  console.error("Usage: ts-node scripts/query_health.ts <agent-wallet-pubkey>");
  process.exit(1);
}

async function main() {
  process.env.ANCHOR_PROVIDER_URL = process.env.ANCHOR_PROVIDER_URL ?? "https://api.devnet.solana.com";
  process.env.ANCHOR_WALLET        = process.env.ANCHOR_WALLET ?? `${process.env.HOME}/.config/solana/id.json`;

  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.HealthOracle as Program<any>;

  const agentWallet = new PublicKey(agentArg);

  const [regPda]  = PublicKey.findProgramAddressSync(
    [Buffer.from("agent"), agentWallet.toBuffer()], program.programId,
  );
  const [certPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("score"), agentWallet.toBuffer()], program.programId,
  );

  const querier = (provider.wallet as anchor.Wallet).publicKey;

  console.log("");
  console.log("Querying Helixor health");
  console.log("  Cluster :", provider.connection.rpcEndpoint);
  console.log("  Querier :", querier.toBase58());
  console.log("  Agent   :", agentWallet.toBase58());
  console.log("  RegPDA  :", regPda.toBase58());
  console.log("  CertPDA :", certPda.toBase58());
  console.log("");

  try {
    const result = await program.methods
      .getHealth()
      .accounts({
        querier,
        agentRegistration: regPda,
        trustCertificate:  certPda,
      })
      .view();

    const sourceKey = Object.keys(result.source)[0];
    const alertKey  = Object.keys(result.alert)[0];

    console.log("Trust Score:");
    console.log(`  agent           ${result.agent.toBase58()}`);
    console.log(`  score           ${result.score} / 1000`);
    console.log(`  alert           ${alertKey.toUpperCase()}`);
    console.log(`  source          ${sourceKey}`);
    console.log(`  is_fresh        ${result.isFresh}`);
    console.log(`  success_rate    ${(result.successRate / 100).toFixed(2)}%`);
    console.log(`  anomaly_flag    ${result.anomalyFlag}`);
    console.log(`  updated_at      ${
      result.updatedAt.toNumber() === 0
        ? "never (provisional)"
        : new Date(result.updatedAt.toNumber() * 1000).toISOString()
    }`);
    console.log("");
  } catch (err: any) {
    console.error("Query failed:");
    console.error(`  ${err.message ?? err}`);
    process.exit(1);
  }
}

main();
