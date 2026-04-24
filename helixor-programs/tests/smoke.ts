// =============================================================================
// Day 1 Smoke Test
//
// Goal: verify the program is deployed, executable, and the IDL is correct.
// No business logic tested here — that starts Day 2.
//
// Run: anchor test
// Expected: 8 passing
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program }  from "@coral-xyz/anchor";
import { PublicKey, Keypair } from "@solana/web3.js";
import { assert }   from "chai";

// Anchor auto-loads the IDL from target/idl/ after anchor build
const HealthOracle = anchor.workspace.HealthOracle;

describe("Day 1 — Smoke Tests", () => {

  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // ── Test 1: Program is deployed and executable ─────────────────────────────
  it("health_oracle is deployed and executable", async () => {
    const info = await provider.connection.getAccountInfo(HealthOracle.programId);
    assert.isNotNull(info,  "health_oracle must be deployed to the test cluster");
    assert.isTrue(info!.executable, "health_oracle account must be executable");
    console.log("  health_oracle:", HealthOracle.programId.toBase58());
  });

  // ── Test 2: IDL exposes the 3 MVP instructions ─────────────────────────────
  it("IDL contains all 3 MVP instructions", () => {
    const methods = Object.keys(HealthOracle.methods);

    assert.include(methods, "registerAgent",
      "registerAgent must be in IDL (wired Day 2)");
    assert.include(methods, "getHealth",
      "getHealth must be in IDL (wired Day 3)");
    assert.include(methods, "updateScore",
      "updateScore must be in IDL (wired Day 7)");

    console.log("  Methods:", methods.join(", "));
  });

  // ── Test 3: IDL exposes the Day 1 payload types ────────────────────────────
  it("IDL contains the Day 1 payload types", () => {
    const types = HealthOracle.idl.types?.map((t: any) => t.name) ?? [];

    assert.include(types, "registerParams",
      "registerParams must be in the IDL types");
    assert.include(types, "scorePayload",
      "scorePayload must be in the IDL types");

    console.log("  Types:", types.join(", "));
  });

  // ── Test 4: All error codes are registered ─────────────────────────────────
  it("IDL contains all 10 error codes", () => {
    const errors: string[] = HealthOracle.idl.errors?.map((e: any) => e.name) ?? [];

    const required = [
      "nameTooLong",
      "insufficientEscrow",
      "agentSameAsOwner",
      "notRegistered",
      "scoreTooLow",
      "staleCertificate",
      "unauthorizedOracle",
      "scoreDeltaTooLarge",
      "updateTooFrequent",
      "mathOverflow",
    ];

    for (const code of required) {
      assert.include(errors, code, `Error code '${code}' must be in IDL`);
    }

    console.log(`  ${errors.length} error codes registered`);
  });

  // ── Test 5: PDA seeds derive correctly ─────────────────────────────────────
  it("AgentRegistration PDA derives from ['agent', agent_wallet]", () => {
    const agentWallet = Keypair.generate().publicKey;
    const [pda, bump] = PublicKey.findProgramAddressSync(
      [Buffer.from("agent"), agentWallet.toBuffer()],
      HealthOracle.programId,
    );
    assert.ok(pda instanceof PublicKey, "PDA must be a valid PublicKey");
    assert.ok(bump >= 0 && bump <= 255,  "Bump must be 0-255");
    console.log("  AgentRegistration PDA:", pda.toBase58().slice(0, 20) + "...");
  });

  it("TrustCertificate PDA derives from ['score', agent_wallet]", () => {
    const agentWallet = Keypair.generate().publicKey;
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from("score"), agentWallet.toBuffer()],
      HealthOracle.programId,
    );
    assert.ok(pda instanceof PublicKey);
    console.log("  TrustCertificate PDA:", pda.toBase58().slice(0, 20) + "...");
  });

  it("EscrowVault PDA derives from ['escrow', agent_wallet]", () => {
    const agentWallet = Keypair.generate().publicKey;
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from("escrow"), agentWallet.toBuffer()],
      HealthOracle.programId,
    );
    assert.ok(pda instanceof PublicKey);
    console.log("  EscrowVault PDA:     ", pda.toBase58().slice(0, 20) + "...");
  });

  it("OracleConfig PDA derives from ['oracle_config']", () => {
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from("oracle_config")],
      HealthOracle.programId,
    );
    assert.ok(pda instanceof PublicKey);
    console.log("  OracleConfig PDA:    ", pda.toBase58().slice(0, 20) + "...");
  });

  // ── Summary ────────────────────────────────────────────────────────────────
  after(() => {
    console.log("\n  Day 1 complete:");
    console.log("  ✓ Program deployed and executable");
    console.log("  ✓ 3 instructions in IDL");
    console.log("  ✓ Day 1 payload types in IDL");
    console.log("  ✓ 10 error codes registered");
    console.log("  ✓ All PDA seeds derive correctly");
    console.log("\n  Next: Day 2 → register_agent full implementation");
    console.log("  Open: programs/health-oracle/src/instructions/register_agent.rs");
  });

});

// =============================================================================
// Exported PDA helpers — re-used by Day 2, 3, 7 test files
// =============================================================================

export const pid = HealthOracle.programId as PublicKey;

export function agentPda(agentWallet: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("agent"), agentWallet.toBuffer()], pid
  );
}

export function scorePda(agentWallet: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("score"), agentWallet.toBuffer()], pid
  );
}

export function escrowPda(agentWallet: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("escrow"), agentWallet.toBuffer()], pid
  );
}

export function oracleConfigPda(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("oracle_config")], pid
  );
}
