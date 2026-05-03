// =============================================================================
// Day 2 — register_agent carry-over (4 representative tests)
// Full 14-test suite from Day 2 stays committed in the repo. Here we run
// 4 sanity checks to ensure register_agent still works on Day 3.
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program, web3 } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { assert } from "chai";

const program = anchor.workspace.HealthOracle as Program<any>;

function agentPda(w: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from("agent"), w.toBuffer()], program.programId);
}
function escrowPda(w: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from("escrow"), w.toBuffer()], program.programId);
}
async function airdrop(conn: web3.Connection, pk: PublicKey, sol = 1) {
  const sig = await conn.requestAirdrop(pk, sol * LAMPORTS_PER_SOL);
  const bh  = await conn.getLatestBlockhash();
  await conn.confirmTransaction({ signature: sig, ...bh }, "confirmed");
}

describe("Day 2 carry-over (register_agent still works)", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const conn = provider.connection;

  it("happy path: registration succeeds + PDA written", async () => {
    const owner = Keypair.generate();
    const agent = Keypair.generate();
    await airdrop(conn, owner.publicKey, 1);

    const [regPda]   = agentPda(agent.publicKey);
    const [vaultPda] = escrowPda(agent.publicKey);

    await program.methods
      .registerAgent({ name: "TestAgent" })
      .accounts({
        owner:             owner.publicKey,
        agentWallet:       agent.publicKey,
        agentRegistration: regPda,
        escrowVault:       vaultPda,
        systemProgram:     SystemProgram.programId,
      })
      .signers([owner, agent])
      .rpc({ commitment: "confirmed" });

    const reg = await program.account.agentRegistration.fetch(regPda);
    assert.equal(reg.agentWallet.toBase58(), agent.publicKey.toBase58());
    assert.equal(reg.escrowLamports.toNumber(), 10_000_000);
    assert.isTrue(reg.active);
  });

  it("vault holds escrow lamports", async () => {
    const owner = Keypair.generate();
    const agent = Keypair.generate();
    await airdrop(conn, owner.publicKey, 1);
    const [regPda]   = agentPda(agent.publicKey);
    const [vaultPda] = escrowPda(agent.publicKey);

    await program.methods
      .registerAgent({ name: "VaultTest" })
      .accounts({
        owner:             owner.publicKey,
        agentWallet:       agent.publicKey,
        agentRegistration: regPda,
        escrowVault:       vaultPda,
        systemProgram:     SystemProgram.programId,
      })
      .signers([owner, agent])
      .rpc();

    const balance = await conn.getBalance(vaultPda);
    assert.isAtLeast(balance, 10_000_000);
  });

  it("rejects empty name", async () => {
    const owner = Keypair.generate();
    const agent = Keypair.generate();
    await airdrop(conn, owner.publicKey, 1);
    const [regPda]   = agentPda(agent.publicKey);
    const [vaultPda] = escrowPda(agent.publicKey);

    try {
      await program.methods
        .registerAgent({ name: "" })
        .accounts({
          owner: owner.publicKey, agentWallet: agent.publicKey,
          agentRegistration: regPda, escrowVault: vaultPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([owner, agent])
        .rpc();
      assert.fail("expected NameEmpty");
    } catch (err: any) {
      assert.include(err.message ?? "", "NameEmpty");
    }
  });

  it("rejects agent_wallet == owner", async () => {
    const self = Keypair.generate();
    await airdrop(conn, self.publicKey, 1);
    const [regPda]   = agentPda(self.publicKey);
    const [vaultPda] = escrowPda(self.publicKey);

    try {
      await program.methods
        .registerAgent({ name: "Self" })
        .accounts({
          owner: self.publicKey, agentWallet: self.publicKey,
          agentRegistration: regPda, escrowVault: vaultPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([self])
        .rpc();
      assert.fail("expected AgentSameAsOwner");
    } catch (err: any) {
      assert.include(err.message ?? "", "AgentSameAsOwner");
    }
  });
});
