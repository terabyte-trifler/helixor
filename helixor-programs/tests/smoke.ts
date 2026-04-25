// =============================================================================
// Smoke Tests — must still pass on Day 2
// Verifies program + IDL shape. Nothing changes Day-to-Day here.
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { PublicKey, Keypair } from "@solana/web3.js";
import { assert } from "chai";

describe("Smoke tests", () => {

  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.HealthOracle;

  it("program is deployed + executable", async () => {
    const info = await provider.connection.getAccountInfo(program.programId);
    assert.isNotNull(info);
    assert.isTrue(info!.executable);
  });

  it("IDL contains all 3 instructions", () => {
    const methods = Object.keys(program.methods);
    assert.include(methods, "registerAgent");
    assert.include(methods, "getHealth");
    assert.include(methods, "updateScore");
  });

  it("IDL contains the Day 2 AgentRegistration account type", () => {
    const accounts = Object.keys(program.account);
    assert.include(accounts, "agentRegistration");
  });

  it("all required error codes are registered", () => {
    const names = program.idl.errors?.map((e: any) => e.name) ?? [];
    for (const code of [
      "nameTooLong", "nameEmpty", "insufficientEscrow",
      "agentSameAsOwner", "notRegistered", "scoreTooLow",
      "staleCertificate", "unauthorizedOracle",
      "scoreDeltaTooLarge", "updateTooFrequent", "mathOverflow",
    ]) {
      assert.include(names, code, `Error code '${code}' must be in IDL`);
    }
  });

  it("PDA seeds derive deterministically", () => {
    const agent = Keypair.generate().publicKey;
    const pid   = program.programId;

    const [a1] = PublicKey.findProgramAddressSync([Buffer.from("agent"),  agent.toBuffer()], pid);
    const [a2] = PublicKey.findProgramAddressSync([Buffer.from("agent"),  agent.toBuffer()], pid);
    const [e1] = PublicKey.findProgramAddressSync([Buffer.from("escrow"), agent.toBuffer()], pid);

    assert.equal(a1.toBase58(), a2.toBase58(), "derivation must be deterministic");
    assert.notEqual(a1.toBase58(), e1.toBase58(), "agent + escrow PDAs must differ");
  });

});
