// Helixor migration — Day 3
// No global PDAs to initialize yet. Day 7 adds OracleConfig.

import * as anchor from "@coral-xyz/anchor";
import { LAMPORTS_PER_SOL } from "@solana/web3.js";

module.exports = async function (provider: anchor.AnchorProvider) {
  anchor.setProvider(provider);

  const program  = anchor.workspace.HealthOracle;
  const consumer = anchor.workspace.ConsumerExample;
  const wallet   = provider.wallet as anchor.Wallet;

  console.log("");
  console.log("Helixor migration");
  console.log("  Cluster :", provider.connection.rpcEndpoint);
  console.log("  Programs:");
  console.log("    health_oracle    =", program.programId.toBase58());
  console.log("    consumer_example =", consumer.programId.toBase58());
  console.log("  Deployer:", wallet.publicKey.toBase58());
  const balance = await provider.connection.getBalance(wallet.publicKey);
  console.log(`  Balance : ${(balance / LAMPORTS_PER_SOL).toFixed(4)} SOL`);
  console.log("  Day 7 will add: OracleConfig PDA initialisation here.");
  console.log("");
};
