#!/usr/bin/env ts-node
// =============================================================================
// scripts/register_test_agent.ts
//
// Registers a test agent on devnet using a pre-generated keypair from keys/.
// Useful for manual Day 2 validation without running the full test suite.
//
// Usage:
//   ts-node scripts/register_test_agent.ts --agent-number 1 --name "MyAgent"
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";
import * as fs from "fs";
import * as path from "path";

const NUM  = process.argv.indexOf("--agent-number");
const NAME = process.argv.indexOf("--name");
const agentNumber = NUM  > 0 ? parseInt(process.argv[NUM + 1], 10) : 1;
const agentName   = NAME > 0 ? process.argv[NAME + 1] : "TestAgent1";

async function main() {
  process.env.ANCHOR_PROVIDER_URL = process.env.ANCHOR_PROVIDER_URL ?? "https://api.devnet.solana.com";
  process.env.ANCHOR_WALLET        = process.env.ANCHOR_WALLET ?? `${process.env.HOME}/.config/solana/id.json`;

  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.HealthOracle as Program<any>;

  // Load agent keypair from keys/
  const keyPath = path.join(__dirname, "..", "keys", `test-agent-${agentNumber}.json`);
  if (!fs.existsSync(keyPath)) {
    console.error(`  [!] keypair not found: ${keyPath}`);
    console.error(`       Run: bash scripts/setup.sh`);
    process.exit(1);
  }
  const agentKp = Keypair.fromSecretKey(
    Buffer.from(JSON.parse(fs.readFileSync(keyPath, "utf8"))),
  );

  const owner = (provider.wallet as anchor.Wallet).publicKey;

  const [regPda]   = PublicKey.findProgramAddressSync(
    [Buffer.from("agent"), agentKp.publicKey.toBuffer()], program.programId,
  );
  const [vaultPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("escrow"), agentKp.publicKey.toBuffer()], program.programId,
  );

  console.log("");
  console.log("Registering agent:");
  console.log("  Cluster :", provider.connection.rpcEndpoint);
  console.log("  Owner   :", owner.toBase58());
  console.log("  Agent   :", agentKp.publicKey.toBase58());
  console.log("  Name    :", agentName);
  console.log("  RegPDA  :", regPda.toBase58());
  console.log("  VaultPDA:", vaultPda.toBase58());
  console.log("");

  const balance = await provider.connection.getBalance(owner);
  console.log(`  Owner balance: ${balance / LAMPORTS_PER_SOL} SOL`);
  if (balance < 0.02 * LAMPORTS_PER_SOL) {
    console.error("  [!] Owner needs at least 0.02 SOL (escrow + rent + fee)");
    console.error("  Run: solana airdrop 1");
    process.exit(1);
  }

  // Check if already registered
  const existing = await provider.connection.getAccountInfo(regPda);
  if (existing) {
    console.log(`  [!] Agent already registered — fetching state...`);
    const reg = await program.account.agentRegistration.fetch(regPda);
    console.log(`  Status: active=${reg.active}, registered_at=${reg.registeredAt.toNumber()}`);
    console.log(`  Nothing to do.`);
    return;
  }

  // Submit registration
  const sig = await program.methods
    .registerAgent({ name: agentName })
    .accounts({
      owner,
      agentWallet:        agentKp.publicKey,
      agentRegistration:  regPda,
      escrowVault:        vaultPda,
      systemProgram:      SystemProgram.programId,
    })
    .rpc({ commitment: "confirmed" });

  console.log(`  ✓ Registered — tx: ${sig}`);

  // Fetch and display
  const reg = await program.account.agentRegistration.fetch(regPda);
  const vaultBal = await provider.connection.getBalance(vaultPda);

  console.log("");
  console.log("Registration state:");
  console.log(`  agent_wallet    = ${reg.agentWallet.toBase58()}`);
  console.log(`  owner_wallet    = ${reg.ownerWallet.toBase58()}`);
  console.log(`  escrow_lamports = ${reg.escrowLamports.toNumber()}`);
  console.log(`  active          = ${reg.active}`);
  console.log(`  registered_at   = ${new Date(reg.registeredAt.toNumber() * 1000).toISOString()}`);
  console.log("");
  console.log(`Vault balance     = ${vaultBal} lamports (${vaultBal / LAMPORTS_PER_SOL} SOL)`);
  console.log("");
  console.log("View on devnet:");
  console.log(`  https://explorer.solana.com/address/${regPda.toBase58()}?cluster=devnet`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
