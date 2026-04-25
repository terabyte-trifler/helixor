// =============================================================================
// Smoke tests — programs deployed, IDL shape correct.
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { PublicKey, Keypair } from "@solana/web3.js";
import { assert } from "chai";

describe("Smoke tests", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program  = anchor.workspace.HealthOracle;
  const consumer = anchor.workspace.ConsumerExample;

  it("health_oracle deployed + executable", async () => {
    const info = await provider.connection.getAccountInfo(program.programId);
    assert.isNotNull(info);
    assert.isTrue(info!.executable);
  });

  it("consumer_example deployed + executable", async () => {
    const info = await provider.connection.getAccountInfo(consumer.programId);
    assert.isNotNull(info);
    assert.isTrue(info!.executable);
  });

  it("all 3 instructions in IDL", () => {
    const m = Object.keys(program.methods);
    assert.include(m, "registerAgent");
    assert.include(m, "getHealth");
    assert.include(m, "updateScore");
  });

  it("AgentRegistration + TrustCertificate accounts in IDL", () => {
    const a = Object.keys(program.account);
    assert.include(a, "agentRegistration");
    assert.include(a, "trustCertificate");
  });

  it("AgentRegistered + HealthQueried events in IDL", () => {
    const events = program.idl.events?.map((e: any) => e.name) ?? [];
    assert.include(events, "AgentRegistered");
    assert.include(events, "HealthQueried");
  });

  it("Day 3 errors registered", () => {
    const names = program.idl.errors?.map((e: any) => e.name) ?? [];
    assert.include(names, "InvalidCertificateAddress");
  });

  it("PDA seeds derive deterministically", () => {
    const agent = Keypair.generate().publicKey;
    const pid = program.programId;
    const [a1] = PublicKey.findProgramAddressSync([Buffer.from("agent"), agent.toBuffer()], pid);
    const [s1] = PublicKey.findProgramAddressSync([Buffer.from("score"), agent.toBuffer()], pid);
    assert.notEqual(a1.toBase58(), s1.toBase58());
  });
});
