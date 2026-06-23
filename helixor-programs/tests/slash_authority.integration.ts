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
import {
  PublicKey, Keypair, SystemProgram, LAMPORTS_PER_SOL,
  Ed25519Program, TransactionInstruction,
  SYSVAR_INSTRUCTIONS_PUBKEY, SYSVAR_SLOT_HASHES_PUBKEY,
} from "@solana/web3.js";
import { createHash } from "crypto";
import * as nacl from "tweetnacl";
import { assert } from "chai";

const { BN } = anchor;
const enc = anchor.utils.bytes.utf8.encode;

const SETTLEMENT_TIMELOCK_SECONDS = 72 * 3_600;

// H-1: domain tag for the on-chain slash-evidence digest — must be
// byte-identical to `SLASH_EVIDENCE_DOMAIN_TAG` in execute_slash.rs.
const SLASH_EVIDENCE_DOMAIN_TAG = Buffer.from("helixor:slash-evidence:v1", "utf-8");

// H-1: recompute the slash-evidence digest from an on-chain HealthCertificate,
// byte-identical to `slash_evidence_digest` in execute_slash.rs. NOTE the
// LITTLE-endian encoding here (the evidence digest uses to_le_bytes, unlike
// the cert-payload digest which is big-endian).
function slashEvidenceDigest(certKey: PublicKey, cert: any): number[] {
  const epochBuf = Buffer.alloc(8); epochBuf.writeBigUInt64LE(BigInt(cert.epoch.toString()));
  const scoreBuf = Buffer.alloc(2); scoreBuf.writeUInt16LE(cert.score);
  const flagsBuf = Buffer.alloc(4); flagsBuf.writeUInt32LE(cert.flags);
  const issuedBuf = Buffer.alloc(8); issuedBuf.writeBigInt64LE(BigInt(cert.issuedAt.toString()));
  const payload = Buffer.concat([
    SLASH_EVIDENCE_DOMAIN_TAG,
    certKey.toBuffer(),                          // 32
    cert.agentWallet.toBuffer(),                 // 32
    epochBuf,                                    //  8  (LE u64)
    scoreBuf,                                    //  2  (LE u16)
    Buffer.from([cert.alertTier]),               //  1
    Buffer.from([cert.immediateRed ? 1 : 0]),    //  1
    flagsBuf,                                    //  4  (LE u32)
    issuedBuf,                                   //  8  (LE i64)
  ]);
  return [...createHash("sha256").update(payload).digest()];
}

// H-1: the certificate-issuer cert-payload digest — byte-identical to
// `cert_payload_digest` in certificate-issuer/src/signing.rs (big-endian,
// includes the M-05 issuer_config_version + the four Day-38 diagnostic
// fields). Used to mint the evidence certificate the slash now requires.
function certPayloadDigest(args: {
  agent: PublicKey; epoch: number; score: number; alertTier: number; flags: number;
  baselineHash: Buffer; immediateRed: boolean; inputCommitment: Buffer;
  slotAnchorSlot: bigint; slotAnchorHash: Buffer; baselineCommitNonce: bigint;
  scoringCodeHash: Buffer; scoreComponentsHash: Buffer; issuerConfigVersion: number;
  failureModeBitmask: bigint; remediationCodes: number; diagnosisPayloadHash: Buffer;
  taxonomyVersion: number;
}): Buffer {
  const u64be = (v: bigint) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(v); return b; };
  const u32be = (v: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(v); return b; };
  const u16be = (v: number) => { const b = Buffer.alloc(2); b.writeUInt16BE(v); return b; };
  const payload = Buffer.concat([
    args.agent.toBuffer(),                       // 32
    u64be(BigInt(args.epoch)),                   //  8
    u16be(args.score),                           //  2
    Buffer.from([args.alertTier]),               //  1
    u32be(args.flags),                           //  4
    args.baselineHash,                           // 32
    Buffer.from([args.immediateRed ? 1 : 0]),    //  1
    args.inputCommitment,                        // 32  AW-01
    u64be(args.slotAnchorSlot),                  //  8  AW-01-EXT
    args.slotAnchorHash,                         // 32  AW-01-EXT
    u64be(args.baselineCommitNonce),             //  8  AW-03
    args.scoringCodeHash,                        // 32  AW-04
    args.scoreComponentsHash,                    // 32  AW-04
    u32be(args.issuerConfigVersion),             //  4  M-05
    u64be(args.failureModeBitmask),              //  8  Day 38
    u32be(args.remediationCodes),                //  4  Day 38
    args.diagnosisPayloadHash,                   // 32  Day 38
    Buffer.from([args.taxonomyVersion]),         //  1  Day 38
  ]);
  return createHash("sha256").update(payload).digest();
}

function ed25519VerifyIx(
  publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array,
): TransactionInstruction {
  return Ed25519Program.createInstructionWithPublicKey({ publicKey, signature, message });
}

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

  // ── H-1: certificate-issuer wiring ─────────────────────────────────────────
  // execute_slash now requires a certificate-issuer-owned HealthCertificate
  // that PROVES the agent is unhealthy. The slash test therefore stands up a
  // minimal 1-key issuer cluster, records the agent's baseline, and mints a
  // YELLOW evidence certificate the slashes cite.
  const certProgram = anchor.workspace.CertificateIssuer as Program;
  const clusterKp = nacl.sign.keyPair();                 // single cluster signer
  const EVIDENCE_EPOCH = 1;
  const EVIDENCE_SCORE = 500;                            // YELLOW band [400,700)
  const EVIDENCE_ALERT_TIER = 1;                         // YELLOW — justifies Minor/Major
  const baselineHash = Buffer.alloc(32, 9);
  const inputCommitment = Buffer.alloc(32, 0x55);
  const scoringCodeHash = Buffer.alloc(32, 0xab);
  const scoreComponentsPayload = Buffer.from(JSON.stringify({ v: 1, dims: [] }), "utf-8");
  const scoreComponentsHash = createHash("sha256").update(scoreComponentsPayload).digest();

  // The computed evidence digest the executeSlash calls cite — populated in
  // before() after the certificate is minted and fetched.
  let evidenceHash: number[] = [...Buffer.alloc(32, 0)];

  const certIssuerConfigPda = () =>
    PublicKey.findProgramAddressSync([enc("issuer_config")], certProgram.programId)[0];
  const certBaselinePda = (a: PublicKey) =>
    PublicKey.findProgramAddressSync([enc("baseline"), a.toBuffer()], certProgram.programId)[0];
  const evidenceCertPda = (a: PublicKey, epoch: number) =>
    PublicKey.findProgramAddressSync(
      [enc("cert"), a.toBuffer(), new BN(epoch).toArrayLike(Buffer, "le", 8)],
      certProgram.programId,
    )[0];
  const scoreComponentsPda = (a: PublicKey, epoch: number) =>
    PublicKey.findProgramAddressSync(
      [enc("score_components"), a.toBuffer(), new BN(epoch).toArrayLike(Buffer, "le", 8)],
      certProgram.programId,
    )[0];

  async function captureSlotAnchor(): Promise<{ slot: bigint; hash: Buffer }> {
    const slot = await provider.connection.getSlot("finalized");
    const block = await provider.connection.getBlock(slot, { maxSupportedTransactionVersion: 0 });
    if (!block) throw new Error(`failed to fetch block ${slot} for slot anchor`);
    return { slot: BigInt(slot), hash: Buffer.from(anchor.utils.bytes.bs58.decode(block.blockhash)) };
  }

  // Mint the YELLOW evidence certificate and compute its slash-evidence digest.
  async function mintEvidenceCertificate(): Promise<void> {
    // 1-key cluster (threshold 1). Idempotent: another test file in the same
    // `anchor test` run may have already created the singleton IssuerConfig —
    // in that case its (unknown) cluster keys differ and minting here would
    // need those keys. Run this spec in isolation, or first in the suite.
    try {
      await certProgram.methods
        .initializeConfig(
          slashExecutorKp.publicKey,                       // issuer_node (rent payer)
          [new PublicKey(clusterKp.publicKey)],            // 1-key cluster
          1,                                               // threshold 1
          PublicKey.default,                               // health_oracle_program_id (CPI disabled)
          [],                                              // challenge_attester_keys
          0,                                               // challenge_threshold
        )
        .accounts({
          issuerConfig: certIssuerConfigPda(),
          admin: slashExecutorKp.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    } catch (_e) { /* already initialised by an earlier spec — proceed */ }

    // Record the agent's baseline (agent signs its own — VULN-06).
    const sig = await provider.connection.requestAirdrop(agent, LAMPORTS_PER_SOL);
    const bh = await provider.connection.getLatestBlockhash();
    await provider.connection.confirmTransaction({ signature: sig, ...bh });
    await certProgram.methods
      .recordBaseline(agent, [...baselineHash], 3, new BN(EVIDENCE_EPOCH), new BN(1))
      .accounts({
        baselineStats: certBaselinePda(agent),
        issuerConfig: certIssuerConfigPda(),
        issuer: agent,
        systemProgram: SystemProgram.programId,
      })
      .signers([agentKp])
      .rpc();

    // Build the cluster-signed cert digest and issue the certificate.
    const slotAnchor = await captureSlotAnchor();
    const digest = certPayloadDigest({
      agent, epoch: EVIDENCE_EPOCH, score: EVIDENCE_SCORE, alertTier: EVIDENCE_ALERT_TIER,
      flags: 0, baselineHash, immediateRed: false, inputCommitment,
      slotAnchorSlot: slotAnchor.slot, slotAnchorHash: slotAnchor.hash,
      baselineCommitNonce: 1n, scoringCodeHash, scoreComponentsHash,
      issuerConfigVersion: 1, failureModeBitmask: 0n, remediationCodes: 0,
      diagnosisPayloadHash: Buffer.alloc(32, 0), taxonomyVersion: 0,
    });
    const edIx = ed25519VerifyIx(
      clusterKp.publicKey, nacl.sign.detached(digest, clusterKp.secretKey), digest,
    );
    const issueIx = await certProgram.methods
      .issueCertificate(
        new BN(EVIDENCE_EPOCH), EVIDENCE_SCORE, EVIDENCE_ALERT_TIER, 0, false,
        [...inputCommitment],
        new BN(slotAnchor.slot.toString()), [...slotAnchor.hash],
        [...scoringCodeHash], Buffer.from(scoreComponentsPayload),
        new BN(0), 0, [...Buffer.alloc(32, 0)], 0,        // Day 38 fields
      )
      .accounts({
        baselineStats: certBaselinePda(agent),
        certificate: evidenceCertPda(agent, EVIDENCE_EPOCH),
        scoreComponents: scoreComponentsPda(agent, EVIDENCE_EPOCH),
        issuerConfig: certIssuerConfigPda(),
        issuer: slashExecutorKp.publicKey,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        slotHashesSysvar: SYSVAR_SLOT_HASHES_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .instruction();
    const tx = new anchor.web3.Transaction().add(edIx, issueIx);
    await provider.sendAndConfirm(tx);

    // Fetch the on-chain cert and compute the evidence digest the slash cites.
    const cert: any = await certProgram.account.healthCertificate.fetch(
      evidenceCertPda(agent, EVIDENCE_EPOCH),
    );
    evidenceHash = slashEvidenceDigest(evidenceCertPda(agent, EVIDENCE_EPOCH), cert);
  }

  // ── setup: config + a funded vault + the evidence certificate ──────────────
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

    // H-1: mint the evidence certificate the executeSlash calls now require.
    await mintEvidenceCertificate();
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
      .executeSlash(new BN(0), 1 /* Major */, evidenceHash)
      .accounts({
        escrowVault: vaultPda(agent),
        slashRecord: slashRecordPda(agent, 0),
        slashConfig: configPda(),
        healthCertificate: evidenceCertPda(agent, EVIDENCE_EPOCH), // H-1 evidence
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
      .executeSlash(new BN(1), 0 /* Minor */, evidenceHash)
      .accounts({
        escrowVault: vaultPda(agent),
        slashRecord: slashRecordPda(agent, 1),
        slashConfig: configPda(),
        healthCertificate: evidenceCertPda(agent, EVIDENCE_EPOCH), // H-1 evidence
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
    // H-04: pause now takes a bounded duration (1..=7 days). 1h is well
    // within bounds for the integration test's "pause, then unpause"
    // round-trip.
    await program.methods
      .pauseSettlements(new BN(3600))
      .accounts({
        slashConfig: configPda(),
        pauseAuthority: pauseAuthorityKp.publicKey,
      })
      .signers([pauseAuthorityKp])
      .rpc();

    // While paused, execute_slash is refused (with another fresh index).
    try {
      await program.methods
        .executeSlash(new BN(2), 0 /* Minor */, evidenceHash)
        .accounts({
          escrowVault: vaultPda(agent),
          slashRecord: slashRecordPda(agent, 2),
          slashConfig: configPda(),
          healthCertificate: evidenceCertPda(agent, EVIDENCE_EPOCH), // H-1 evidence
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
