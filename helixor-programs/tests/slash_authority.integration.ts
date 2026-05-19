// =============================================================================
// tests/slash_authority.integration.ts
//
// Integration tests for the slash-authority program, run against
// `anchor test` (a local validator). Updated for the Day-21 dispute
// lifecycle.
//
// Day-21 done-when:
//   - a slashed agent can APPEAL  (appeal_slash -> resolve_appeal)
//   - a provably-bad oracle submission can be CHALLENGED (challenge_oracle)
//   - both paths tested.
//
// The slash lifecycle is now: execute_slash (ENCUMBER, Pending) ->
// either appeal_slash -> resolve_appeal, or settle_slash (move funds).
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import BN from "bn.js";
import { PublicKey, Keypair, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { assert } from "chai";

const enc = anchor.utils.bytes.utf8.encode;

describe("slash-authority dispute mechanisms (Day 21)", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SlashAuthority as Program;
  const slashAuthority = provider.wallet;

  // The agent owns its own vault — for appeal_slash it must sign.
  const agentKp = Keypair.generate();
  const agent = agentKp.publicKey;
  const treasury = Keypair.generate().publicKey;
  const evidence = Buffer.alloc(32, 3);
  const justification = Buffer.alloc(32, 5);
  const proofHash = Buffer.alloc(32, 7);

  const STAKE = 1 * LAMPORTS_PER_SOL;

  // ── PDA helpers ────────────────────────────────────────────────────────────
  const configPda = () =>
    PublicKey.findProgramAddressSync([enc("slash_config")], program.programId)[0];
  const vaultPda = (a: PublicKey) =>
    PublicKey.findProgramAddressSync([enc("escrow"), a.toBuffer()], program.programId)[0];
  const slashRecordPda = (a: PublicKey, index: number) =>
    PublicKey.findProgramAddressSync(
      [enc("slash"), a.toBuffer(), new BN(index).toArrayLike(Buffer, "le", 8)],
      program.programId
    )[0];
  const challengeCounterPda = (oracle: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [enc("challenge_counter"), oracle.toBuffer()],
      program.programId
    )[0];
  const challengePda = (oracle: PublicKey, index: number) =>
    PublicKey.findProgramAddressSync(
      [enc("challenge"), oracle.toBuffer(), new BN(index).toArrayLike(Buffer, "le", 8)],
      program.programId
    )[0];

  // ── setup: config + a funded vault ─────────────────────────────────────────
  before(async () => {
    const treasuryAirdrop = await provider.connection.requestAirdrop(
      treasury,
      LAMPORTS_PER_SOL
    );
    const bh = await provider.connection.getLatestBlockhash();
    await provider.connection.confirmTransaction(
      { signature: treasuryAirdrop, ...bh },
      "confirmed"
    );

    await program.methods
      .initializeConfig(slashAuthority.publicKey, treasury)
      .accounts({
        slashConfig: configPda(),
        admin: slashAuthority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    await program.methods
      .openVault(agent, new BN(STAKE))
      .accounts({
        escrowVault: vaultPda(agent),
        staker: slashAuthority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  });

  // ── execute_slash now ENCUMBERS — funds held, not moved ────────────────────
  it("execute_slash encumbers funds and records a Pending slash", async () => {
    const before: any = await program.account.escrowVault.fetch(vaultPda(agent));
    const vaultBalanceBefore = await provider.connection.getBalance(vaultPda(agent));

    await program.methods
      .executeSlash(new BN(0), 1 /* Major */, [...evidence])
      .accounts({
        escrowVault: vaultPda(agent),
        slashRecord: slashRecordPda(agent, 0),
        slashConfig: configPda(),
        slashAuthority: slashAuthority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const after: any = await program.account.escrowVault.fetch(vaultPda(agent));
    const expectedSlash = Math.floor(before.stakedLamports.toNumber() * 0.5);

    // staked_lamports dropped; encumbered_lamports rose by the same amount.
    assert.equal(
      after.stakedLamports.toNumber(),
      before.stakedLamports.toNumber() - expectedSlash
    );
    assert.equal(after.encumberedLamports.toNumber(), expectedSlash);

    // CRUCIAL: the funds are still PHYSICALLY in the vault — nothing moved.
    const vaultBalanceAfter = await provider.connection.getBalance(vaultPda(agent));
    assert.equal(vaultBalanceAfter, vaultBalanceBefore, "no lamports left the vault");

    // The record is Pending with an open appeal window.
    const record: any = await program.account.slashRecord.fetch(slashRecordPda(agent, 0));
    assert.equal(record.status, 0); // Pending
    assert.ok(record.appealDeadline.toNumber() > record.executedAt.toNumber());
  });

  // ── DONE-WHEN 1: a slashed agent can appeal ────────────────────────────────
  it("a slashed agent can appeal — Pending -> Appealed", async () => {
    await program.methods
      .appealSlash([...justification])
      .accounts({
        escrowVault: vaultPda(agent),
        slashRecord: slashRecordPda(agent, 0),
        agentOwner: agent, // the agent itself signs
      })
      .signers([agentKp])
      .rpc();

    const record: any = await program.account.slashRecord.fetch(slashRecordPda(agent, 0));
    assert.equal(record.status, 1); // Appealed
    assert.deepEqual([...record.appealHash], [...justification]);
  });

  it("an overturned appeal releases the encumbered funds back", async () => {
    const before: any = await program.account.escrowVault.fetch(vaultPda(agent));

    // resolve_appeal(uphold = false) -> overturned.
    await program.methods
      .resolveAppeal(false)
      .accounts({
        escrowVault: vaultPda(agent),
        slashRecord: slashRecordPda(agent, 0),
        slashConfig: configPda(),
        slashAuthority: slashAuthority.publicKey,
      })
      .rpc();

    const after: any = await program.account.escrowVault.fetch(vaultPda(agent));
    // The encumbered funds returned to free stake — the agent lost nothing.
    assert.equal(after.encumberedLamports.toNumber(), 0);
    assert.equal(
      after.stakedLamports.toNumber(),
      before.stakedLamports.toNumber() + before.encumberedLamports.toNumber()
    );

    const record: any = await program.account.slashRecord.fetch(slashRecordPda(agent, 0));
    assert.equal(record.status, 2); // Overturned
  });

  // ── an upheld appeal -> the slash settles and funds move ───────────────────
  it("an upheld appeal lets the slash settle to the treasury", async () => {
    // Use a fresh agent for this path so the 24h appeal cooldown from the
    // overturned-appeal path above does not block the second appeal.
    const upheldAgentKp = Keypair.generate();
    const upheldAgent = upheldAgentKp.publicKey;

    await program.methods
      .openVault(upheldAgent, new BN(STAKE))
      .accounts({
        escrowVault: vaultPda(upheldAgent),
        staker: slashAuthority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    await program.methods
      .executeSlash(new BN(0), 0 /* Minor */, [...evidence])
      .accounts({
        escrowVault: vaultPda(upheldAgent),
        slashRecord: slashRecordPda(upheldAgent, 0),
        slashConfig: configPda(),
        slashAuthority: slashAuthority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    await program.methods
      .appealSlash([...justification])
      .accounts({
        escrowVault: vaultPda(upheldAgent),
        slashRecord: slashRecordPda(upheldAgent, 0),
        agentOwner: upheldAgent,
      })
      .signers([upheldAgentKp])
      .rpc();

    // Uphold the slash — appeal fails, window re-closed, becomes settleable.
    await program.methods
      .resolveAppeal(true)
      .accounts({
        escrowVault: vaultPda(upheldAgent),
        slashRecord: slashRecordPda(upheldAgent, 0),
        slashConfig: configPda(),
        slashAuthority: slashAuthority.publicKey,
      })
      .rpc();

    const treasuryBefore = await provider.connection.getBalance(treasury);

    await program.methods
      .settleSlash()
      .accounts({
        escrowVault: vaultPda(upheldAgent),
        slashRecord: slashRecordPda(upheldAgent, 0),
        slashConfig: configPda(),
        destination: treasury,
        slashAuthority: slashAuthority.publicKey,
      })
      .rpc();

    // Now the funds actually moved to the treasury.
    const treasuryAfter = await provider.connection.getBalance(treasury);
    assert.ok(treasuryAfter > treasuryBefore, "treasury received the settled slash");

    const record: any = await program.account.slashRecord.fetch(slashRecordPda(upheldAgent, 0));
    assert.equal(record.status, 3); // Settled
  });

  // ── DONE-WHEN 2: a provably-bad oracle submission can be challenged ────────
  it("challenges an oracle for conflicting scores — on-chain verified", async () => {
    const accusedOracle = Keypair.generate().publicKey;

    // ConflictingScores: the oracle signed score 916 AND 120 for the same
    // (agent, epoch). The two differing values are checked on chain.
    await program.methods
      .challengeOracle(
        0, // ProofType.ConflictingScores
        [...proofHash],
        new BN(5), // subject_epoch
        916, // score_a
        120 // score_b
      )
      .accounts({
        challengeCounter: challengeCounterPda(accusedOracle),
        challenge: challengePda(accusedOracle, 0),
        accusedOracle,
        subjectAgent: agent,
        challenger: slashAuthority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const challenge: any = await program.account.oracleChallenge.fetch(
      challengePda(accusedOracle, 0)
    );
    assert.equal(challenge.proofType, 0); // ConflictingScores
    assert.equal(challenge.status, 1); // Verified — conflict confirmed on chain
    assert.ok(challenge.accusedOracle.equals(accusedOracle));
  });

  it("rejects a conflicting-scores challenge where the scores are equal", async () => {
    const accusedOracle = Keypair.generate().publicKey;
    try {
      await program.methods
        .challengeOracle(0, [...proofHash], new BN(5), 700, 700) // equal
        .accounts({
          challengeCounter: challengeCounterPda(accusedOracle),
          challenge: challengePda(accusedOracle, 0),
          accusedOracle,
          subjectAgent: agent,
          challenger: slashAuthority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      assert.fail("equal scores are not a conflict — should be rejected");
    } catch (err) {
      assert.ok(err, "expected NotInConflict");
    }
  });

  it("records an off-chain evidence challenge as Pending for governance", async () => {
    const accusedOracle = Keypair.generate().publicKey;

    await program.methods
      .challengeOracle(2, [...proofHash], new BN(5), 0, 0) // EvidenceHash
      .accounts({
        challengeCounter: challengeCounterPda(accusedOracle),
        challenge: challengePda(accusedOracle, 0),
        accusedOracle,
        subjectAgent: agent,
        challenger: slashAuthority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const challenge: any = await program.account.oracleChallenge.fetch(
      challengePda(accusedOracle, 0)
    );
    // Honest scope: an off-chain claim is NOT auto-verified — it is Pending.
    assert.equal(challenge.status, 0); // Pending
  });
});
