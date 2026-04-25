// =============================================================================
// Helixor Migration — runs after `anchor deploy`
//
// Day 2: no-op (no global PDAs to initialize yet).
// Day 7: will initialize OracleConfig PDA with the oracle node pubkey.
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { LAMPORTS_PER_SOL } from "@solana/web3.js";

module.exports = async function (provider: anchor.AnchorProvider) {
  anchor.setProvider(provider);

  const program = anchor.workspace.HealthOracle;
  const wallet  = provider.wallet as anchor.Wallet;

  console.log("");
  console.log("══════════════════════════════════════");
  console.log("  Helixor Migration");
  console.log("══════════════════════════════════════");
  console.log("  Cluster :", provider.connection.rpcEndpoint);
  console.log("  Program :", program.programId.toBase58());
  console.log("  Deployer:", wallet.publicKey.toBase58());

  const balance = await provider.connection.getBalance(wallet.publicKey);
  console.log(`  Balance : ${(balance / LAMPORTS_PER_SOL).toFixed(4)} SOL`);

  console.log("");
  console.log("  Day 2: no migrations needed (AgentRegistration PDAs are");
  console.log("         created per-agent, not globally).");
  console.log("  Day 7: will initialize OracleConfig here.");
  console.log("══════════════════════════════════════");
  console.log("");
};
