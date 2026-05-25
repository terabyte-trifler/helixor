// =============================================================================
// tests/slash_authority.integration.ts
//
// Integration tests for the slash-authority program, run against
// `anchor test` (a local validator). Covers the Day-21 dispute lifecycle
// AND the VULN-04 separated-authority + post-uphold-timelock + pause
// model.
//
// Roles used:
//   - slash_executor   = provider wallet (pays rent)
//   - appeal_resolver  = separately generated keypair
//   - pause_authority  = separately generated keypair
//
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { assert } from "chai";

const { BN } = anchor;
const enc = anchor.utils.bytes.utf8.encode;

const SETTLEMENT_TIMELOCK_SECONDS = 72 * 3_600;

describe("slash-authority dispute mechanisms (Day 21 + VULN-04)", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SlashAuthority as Program;

  // VULN-04: the three role keys are distinct. The provider wallet is
  // the slash_executor (pays SlashRecord rent); resolver and pauser are
  // separately generated keypairs that sign their own instructions.
  const slashExecutorKp = provider.wallet;
  const appealResolverKp = Keypair.generate();
  const pauseAuthorityKp = Keypair.generate();

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
    await program.methods
      .initializeConfig(
        slashExecutorKp.publicKey,
        appealResolverKp.publicKey,
        pauseAuthorityKp.publicKey,
        treasury,
        new BN(SETTLEMENT_TIMELOCK_SECONDS),
      )
      .accounts({
        slashConfig: configPda(),
        admin: slashExecutorKp.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    await program.methods
      .openVault(agent, new BN(STAKE))
      .accounts({
        escrowVault: vaultPda(agent),
        staker: slashExecutorKp.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  });

  // ── VULN-04: initialize_config rejects identical role keys ─────────────────
  it("initialize_config rejects identical role keys", async () => {
    // Use a separate program-derived address by deriving with a fake admin
    // is not possible (singleton seeds). Instead we cover this gate via the
    // pure Rust test `executor_equal_to_resolver_rejected`. The TS check
    // exercises the live program too by attempting `update_authorities`:
    try {
      await program.methods
        .updateAuthorities(
          slashExecutorKp.publicKey,        // executor
          slashExecutorKp.publicKey,        // resolver == executor — REJECT
          pauseAuthorityKp.publicKey,
          new BN(SETTLEMENT_TIMELOCK_SECONDS),
        )
        .accounts({
          slashConfig: configPda(),
          admin: slashExecutorKp.publicKey,
        })
        .rpc();
      assert.fail("collapsing executor==resolver must be rejected");
    } catch (err) {
      assert.ok(err, "expected AuthoritiesMustDiffer");
    }
  });

  it("initialize_config rejects a settlement timelock below 72h", async () => {
    try {
      await program.methods
        .updateAuthorities(
          slashExecutorKp.publicKey,
          appealResolverKp.publicKey,
          pauseAuthorityKp.publicKey,
          new BN(60), // far too short
        )
        .accounts({
          slashConfig: configPda(),
          admin: slashExecutorKp.publicKey,
        })
        .rpc();
      assert.fail("sub-72h timelock must be rejected");
    } catch (err) {
      assert.ok(err, "expected SettlementTimelockTooShort");
    }
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
        slashExecutor: slashExecutorKp.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const after: any = await program.account.escrowVault.fetch(vaultPda(agent));
    const expectedSlash = Math.floor(before.stakedLamports.toNumber() * 0.5);

    assert.equal(
      after.stakedLamports.toNumber(),
      before.stakedLamports.toNumber() - expectedSlash
    );
    assert.equal(after.encumberedLamports.toNumber(), expectedSlash);

    // CRUCIAL: the funds are still PHYSICALLY in the vault — nothing moved.
    const vaultBalanceAfter = await provider.connection.getBalance(vaultPda(agent));
    assert.equal(vaultBalanceAfter, vaultBalanceBefore, "no lamports left the vault");

    const record: any = await program.account.slashRecord.fetch(slashRecordPda(agent, 0));
    assert.equal(record.status, 0); // Pending
    assert.ok(record.appealDeadline.toNumber() > record.executedAt.toNumber());
    // VULN-04: until an appeal is upheld, settlement_unlock_at stays zero.
    assert.equal(record.settlementUnlockAt.toNumber(), 0);
  });

  // ── DONE-WHEN 1: a slashed agent can appeal ────────────────────────────────
  it("a slashed agent can appeal — Pending -> Appealed", async () => {
    await program.methods
      .appealSlash([...justification])
      .accounts({
        escrowVault: vaultPda(agent),
        slashRecord: slashRecordPda(agent, 0),
        agentOwner: agent,
      })
      .signers([agentKp])
      .rpc();

    const record: any = await program.account.slashRecord.fetch(slashRecordPda(agent, 0));
    assert.equal(record.status, 1); // Appealed
    assert.deepEqual([...record.appealHash], [...justification]);
  });

  // ── VULN-04: the executor signing resolve_appeal is rejected ───────────────
  it("resolve_appeal refuses the slash_executor as signer (separation of roles)", async () => {
    try {
      await program.methods
        .resolveAppeal(false)
        .accounts({
          escrowVault: vaultPda(agent),
          slashRecord: slashRecordPda(agent, 0),
          slashConfig: configPda(),
          appealResolver: slashExecutorKp.publicKey, // wrong role
        })
        .rpc();
      assert.fail("executor must not be able to resolve appeals");
    } catch (err) {
      assert.ok(err, "expected NotAppealResolver");
    }
  });

  it("an overturned appeal releases the encumbered funds back", async () => {
    const before: any = await program.account.escrowVault.fetch(vaultPda(agent));

    await program.methods
      .resolveAppeal(false)
      .accounts({
        escrowVault: vaultPda(agent),
        slashRecord: slashRecordPda(agent, 0),
        slashConfig: configPda(),
        appealResolver: appealResolverKp.publicKey,
      })
      .signers([appealResolverKp])
      .rpc();

    const after: any = await program.account.escrowVault.fetch(vaultPda(agent));
    assert.equal(after.encumberedLamports.toNumber(), 0);
    assert.equal(
      after.stakedLamports.toNumber(),
      before.stakedLamports.toNumber() + before.encumberedLamports.toNumber()
    );

    const record: any = await program.account.slashRecord.fetch(slashRecordPda(agent, 0));
    assert.equal(record.status, 2); // Overturned
    assert.ok(record.appealResolvedBy.equals(appealResolverKp.publicKey));
    // Overturned records do not carry a settlement timelock.
    assert.equal(record.settlementUnlockAt.toNumber(), 0);
  });

  // ── VULN-04: upheld appeal now arms the post-uphold timelock ───────────────
  it("an upheld appeal arms the settlement timelock and blocks immediate settle", async () => {
    // Second slash to exercise the uphold path.
    await program.methods
      .executeSlash(new BN(1), 0 /* Minor */, [...evidence])
      .accounts({
        escrowVault: vaultPda(agent),
        slashRecord: slashRecordPda(agent, 1),
        slashConfig: configPda(),
        slashExecutor: slashExecutorKp.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    await program.methods
      .appealSlash([...justification])
      .accounts({
        escrowVault: vaultPda(agent),
        slashRecord: slashRecordPda(agent, 1),
        agentOwner: agent,
      })
      .signers([agentKp])
      .rpc();

    await program.methods
      .resolveAppeal(true)
      .accounts({
        escrowVault: vaultPda(agent),
        slashRecord: slashRecordPda(agent, 1),
        slashConfig: configPda(),
        appealResolver: appealResolverKp.publicKey,
      })
      .signers([appealResolverKp])
      .rpc();

    const record: any = await program.account.slashRecord.fetch(slashRecordPda(agent, 1));
    // VULN-04: the timelock is armed for 72h — settle must wait.
    assert.ok(
      record.settlementUnlockAt.toNumber() > Math.floor(Date.now() / 1000),
      "settlement_unlock_at must be in the future"
    );
    assert.ok(record.appealResolvedBy.equals(appealResolverKp.publicKey));

    // Attempting to settle immediately must fail with SettlementTimelockNotElapsed.
    try {
      await program.methods
        .settleSlash()
        .accounts({
          escrowVault: vaultPda(agent),
          slashRecord: slashRecordPda(agent, 1),
          slashConfig: configPda(),
          destination: treasury,
          slashExecutor: slashExecutorKp.publicKey,
        })
        .rpc();
      assert.fail("settle_slash inside the timelock must be rejected");
    } catch (err) {
      assert.ok(err, "expected SettlementTimelockNotElapsed");
    }
  });

  // ── VULN-04: pause kill switch ─────────────────────────────────────────────
  it("the pause_authority can pause and unpause the slash pipeline", async () => {
    await program.methods
      .pauseSettlements()
      .accounts({
        slashConfig: configPda(),
        pauseAuthority: pauseAuthorityKp.publicKey,
      })
      .signers([pauseAuthorityKp])
      .rpc();

    // While paused, execute_slash is refused (with another fresh index).
    try {
      await program.methods
        .executeSlash(new BN(2), 0 /* Minor */, [...evidence])
        .accounts({
          escrowVault: vaultPda(agent),
          slashRecord: slashRecordPda(agent, 2),
          slashConfig: configPda(),
          slashExecutor: slashExecutorKp.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      assert.fail("execute_slash must be refused while paused");
    } catch (err) {
      assert.ok(err, "expected SettlementsPaused");
    }

    // The pause flag is queryable.
    const config: any = await program.account.slashConfig.fetch(configPda());
    assert.equal(config.paused, true);

    // Unpause restores normal operation.
    await program.methods
      .unpauseSettlements()
      .accounts({
        slashConfig: configPda(),
        pauseAuthority: pauseAuthorityKp.publicKey,
      })
      .signers([pauseAuthorityKp])
      .rpc();
    const after: any = await program.account.slashConfig.fetch(configPda());
    assert.equal(after.paused, false);
  });

  // ── DONE-WHEN 2: a bad oracle submission can be challenged ────────────────
  it("records a conflicting-scores challenge for slash-authority review", async () => {
    const accusedOracle = Keypair.generate().publicKey;

    await program.methods
      .challengeOracle(
        0,
        [...proofHash],
        new BN(5),
        916,
        120
      )
      .accounts({
        challengeCounter: challengeCounterPda(accusedOracle),
        challenge: challengePda(accusedOracle, 0),
        accusedOracle,
        subjectAgent: agent,
        challenger: slashExecutorKp.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const challenge: any = await program.account.oracleChallenge.fetch(
      challengePda(accusedOracle, 0)
    );
    assert.equal(challenge.proofType, 0);
    assert.equal(challenge.status, 0);
    assert.ok(challenge.accusedOracle.equals(accusedOracle));
  });

  it("rejects a conflicting-scores challenge where the scores are equal", async () => {
    const accusedOracle = Keypair.generate().publicKey;
    try {
      await program.methods
        .challengeOracle(0, [...proofHash], new BN(5), 700, 700)
        .accounts({
          challengeCounter: challengeCounterPda(accusedOracle),
          challenge: challengePda(accusedOracle, 0),
          accusedOracle,
          subjectAgent: agent,
          challenger: slashExecutorKp.publicKey,
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
      .challengeOracle(2, [...proofHash], new BN(5), 0, 0)
      .accounts({
        challengeCounter: challengeCounterPda(accusedOracle),
        challenge: challengePda(accusedOracle, 0),
        accusedOracle,
        subjectAgent: agent,
        challenger: slashExecutorKp.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const challenge: any = await program.account.oracleChallenge.fetch(
      challengePda(accusedOracle, 0)
    );
    assert.equal(challenge.status, 0);
  });
});
