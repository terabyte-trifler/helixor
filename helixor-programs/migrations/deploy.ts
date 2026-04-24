// =============================================================================
// Helixor Migration — runs once after `anchor deploy`
//
// Day 1: no-op (OracleConfig instruction wired on Day 7)
// Day 7: initialises OracleConfig PDA with oracle node public key
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { PublicKey, SystemProgram, SYSVAR_RENT_PUBKEY, LAMPORTS_PER_SOL } from "@solana/web3.js";

module.exports = async function (provider: anchor.AnchorProvider) {
  anchor.setProvider(provider);

  const program = anchor.workspace.HealthOracle;
  const wallet  = provider.wallet as anchor.Wallet;
  const conn    = provider.connection;

  console.log("\n══════════════════════════════════════");
  console.log("  Helixor Migration");
  console.log("══════════════════════════════════════");
  console.log("  Cluster :", conn.rpcEndpoint);
  console.log("  Deployer:", wallet.publicKey.toBase58());
  console.log("  Program :", program.programId.toBase58());

  // ── Derive PDAs ────────────────────────────────────────────────────────────
  const [oracleConfigPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("oracle_config")],
    program.programId,
  );
  console.log("\n  OracleConfig PDA:", oracleConfigPda.toBase58());

  // ── Check balance ──────────────────────────────────────────────────────────
  const balance = await conn.getBalance(wallet.publicKey);
  console.log(`  Deployer balance: ${(balance / LAMPORTS_PER_SOL).toFixed(4)} SOL`);
  if (balance < 0.1 * LAMPORTS_PER_SOL) {
    console.warn("  ⚠ Low balance — run: solana airdrop 2 (devnet)");
  }

  // ── OracleConfig ───────────────────────────────────────────────────────────
  const oracleInfo = await conn.getAccountInfo(oracleConfigPda);
  if (oracleInfo) {
    console.log("\n  [skip] OracleConfig already initialised");
  } else {
    console.log("\n  [Day 7] OracleConfig will be initialised once update_score is wired");
    console.log("          To initialise: ts-node scripts/init_oracle.ts");
  }

  // ── Summary ────────────────────────────────────────────────────────────────
  console.log("\n══════════════════════════════════════");
  console.log("  Migration complete ✓");
  console.log("  Next steps:");
  console.log("    Day 2: implement register_agent");
  console.log("    Day 3: implement get_health");
  console.log("    Day 7: implement update_score + run init_oracle.ts");
  console.log("══════════════════════════════════════\n");
};
