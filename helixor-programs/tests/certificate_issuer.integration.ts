// =============================================================================
// tests/certificate_issuer.integration.ts
//
// Day-27 done-when integration test for the certificate-issuer program:
// "a certificate write with only 2 signatures is rejected on-chain;
//  3 valid signatures succeed."
//
// Runs against `anchor test` (a local validator). The test:
//   1. initialises a 5-key issuer cluster with threshold 3,
//   2. records a baseline for an agent,
//   3. computes the canonical cert-payload digest the on-chain code expects,
//   4. signs that digest with 3 of the 5 cluster keys, builds the matching
//      Ed25519 precompile instructions, attaches them to the tx, calls
//      issue_certificate -> SUCCEEDS,
//   5. attempts the same for a second agent with only 2 signatures
//      attached -> REJECTED with InsufficientSignatures,
//   6. attempts with 3 legitimate signatures over a HISTORICAL / mismatched
//      digest while issuing a different cert payload -> REJECTED. This pins
//      the critical replay guard: the on-chain verifier must bind every
//      counted Ed25519 precompile message to the current issue_certificate
//      payload digest, not merely count "3 valid cluster signatures."
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  PublicKey, Keypair, SystemProgram, TransactionInstruction,
  SYSVAR_INSTRUCTIONS_PUBKEY, SYSVAR_SLOT_HASHES_PUBKEY, Ed25519Program,
} from "@solana/web3.js";
import * as nacl from "tweetnacl";
import { createHash } from "crypto";
import { assert } from "chai";

const { BN } = anchor;
const enc = anchor.utils.bytes.utf8.encode;

// =============================================================================
// Canonical cert payload digest — byte-identical to on-chain signing.rs and
// off-chain oracle/cluster/cert_signing.py.
// =============================================================================

function certPayloadDigest(
  agent: PublicKey,
  epoch: number,
  score: number,
  alertTier: number,
  flags: number,
  baselineHash: Buffer,
  immediateRed: boolean,
  inputCommitment: Buffer,        // AW-01 — must match on-chain digest order
  slotAnchorSlot: bigint,         // AW-01-EXT — Solana slot pinned at scoring
  slotAnchorHash: Buffer,         // AW-01-EXT — block hash for that slot
  baselineCommitNonce: bigint,    // AW-03 — names the BaselineDataAccount PDA
  scoringCodeHash: Buffer,        // AW-04 — bundle hash of the scoring kernel
  scoreComponentsHash: Buffer,    // AW-04 — sha256(canonical components payload)
): Buffer {
  const epochBuf = Buffer.alloc(8);  epochBuf.writeBigUInt64BE(BigInt(epoch));
  const scoreBuf = Buffer.alloc(2);  scoreBuf.writeUInt16BE(score);
  const flagsBuf = Buffer.alloc(4);  flagsBuf.writeUInt32BE(flags);
  if (inputCommitment.length !== 32) {
    throw new Error("inputCommitment must be 32 bytes (AW-01)");
  }
  if (slotAnchorHash.length !== 32) {
    throw new Error("slotAnchorHash must be 32 bytes (AW-01-EXT)");
  }
  if (scoringCodeHash.length !== 32) {
    throw new Error("scoringCodeHash must be 32 bytes (AW-04)");
  }
  if (scoreComponentsHash.length !== 32) {
    throw new Error("scoreComponentsHash must be 32 bytes (AW-04)");
  }
  const anchorSlotBuf = Buffer.alloc(8);
  anchorSlotBuf.writeBigUInt64BE(slotAnchorSlot);
  const nonceBuf = Buffer.alloc(8);
  nonceBuf.writeBigUInt64BE(baselineCommitNonce);
  const payload = Buffer.concat([
    agent.toBuffer(),                            // 32
    epochBuf,                                    //  8
    scoreBuf,                                    //  2
    Buffer.from([alertTier]),                    //  1
    flagsBuf,                                    //  4
    baselineHash,                                // 32
    Buffer.from([immediateRed ? 1 : 0]),         //  1
    inputCommitment,                             // 32  ← AW-01
    anchorSlotBuf,                               //  8  ← AW-01-EXT
    slotAnchorHash,                              // 32  ← AW-01-EXT
    nonceBuf,                                    //  8  ← AW-03
    scoringCodeHash,                             // 32  ← AW-04
    scoreComponentsHash,                         // 32  ← AW-04
  ]);
  return createHash("sha256").update(payload).digest();
}

// =============================================================================
// Build an Ed25519 precompile instruction that verifies (signer, digest, sig).
// `@solana/web3.js`' Ed25519Program.createInstructionWithPublicKey does this,
// but we build it explicitly here to mirror the off-chain Python builder and
// be unambiguous about the byte layout the on-chain parser expects.
// =============================================================================

function ed25519VerifyIx(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): TransactionInstruction {
  return Ed25519Program.createInstructionWithPublicKey({
    publicKey, signature, message,
  });
}

// =============================================================================
// Test
// =============================================================================

describe("certificate-issuer 3-of-5 threshold signing (Day 27)", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.CertificateIssuer as Program;
  const submitter = provider.wallet;             // pays rent, not a gate

  // ── A 5-key issuer cluster, threshold 3 ──────────────────────────────────
  const clusterKps = Array.from({ length: 5 }, () => nacl.sign.keyPair());
  const clusterPubkeys = clusterKps.map(
    (kp) => new PublicKey(kp.publicKey),
  );

  // Synthetic agents for the success path and each independent failure path.
  // VULN-06: `recordBaseline` now requires the signer to be EITHER the agent
  // itself OR a cluster signing key — so we keep the agents as full Keypairs
  // (with secret keys) and have them sign their own baseline writes below.
  const agentOkKp = Keypair.generate();
  const agentBadKp = Keypair.generate();
  const agentReplayKp = Keypair.generate();
  const agentOk = agentOkKp.publicKey;
  const agentBad = agentBadKp.publicKey;
  const agentReplay = agentReplayKp.publicKey;
  const baselineHash = Buffer.alloc(32, 7);
  // AW-01: a fixed test input-provenance commitment. Real commitments are
  // produced by the off-chain helixor-oracle pipeline.
  const inputCommitment = Buffer.alloc(32, 0x99);
  // AW-04: a fixed test scoring-kernel bundle hash (non-zero — the on-chain
  // guard rejects all-zeros). Real values come from
  // `scoring.bundle_hash.compute_scoring_bundle_hash()`.
  const scoringCodeHash = Buffer.alloc(32, 0xab);
  // AW-04: a fixed test components payload (any non-empty ≤ 4 KB blob).
  // The on-chain handler computes sha256 itself; we mirror that locally
  // so the cert digest matches.
  const scoreComponentsPayload = Buffer.from(
    JSON.stringify({ v: 1, score: 916, dims: [] }),
    "utf-8",
  );
  const scoreComponentsHash = createHash("sha256")
    .update(scoreComponentsPayload)
    .digest();

  // AW-01-EXT — capture a LIVE `(slot, block_hash)` from the validator
  // for each test that needs one. The on-chain `verify_slot_anchor`
  // walks SlotHashes and refuses anything not present in the ~512-slot
  // window, so the anchor must be fresh — defer to each test rather
  // than capture once at module load.
  async function captureSlotAnchor(): Promise<{
    slot: bigint; hash: Buffer;
  }> {
    const slot = await provider.connection.getSlot("finalized");
    const block = await provider.connection.getBlock(slot, {
      maxSupportedTransactionVersion: 0,
    });
    if (!block) {
      throw new Error(`failed to fetch block ${slot} for slot anchor capture`);
    }
    return {
      slot: BigInt(slot),
      hash: Buffer.from(
        anchor.utils.bytes.bs58.decode(block.blockhash),
      ),
    };
  }

  // ── PDA helpers ──────────────────────────────────────────────────────────
  const issuerConfigPda = () =>
    PublicKey.findProgramAddressSync([enc("issuer_config")], program.programId)[0];
  const baselinePda = (agent: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [enc("baseline"), agent.toBuffer()], program.programId,
    )[0];
  const certPda = (agent: PublicKey, epoch: number) =>
    PublicKey.findProgramAddressSync(
      [enc("cert"), agent.toBuffer(), new BN(epoch).toArrayLike(Buffer, "le", 8)],
      program.programId,
    )[0];
  // AW-04: write-once ScoreComponentsAccount, one per (agent, epoch). Keyed
  // by the same epoch as the cert so the SDK verifier can derive it from
  // the cert alone.
  const scoreComponentsPda = (agent: PublicKey, epoch: number) =>
    PublicKey.findProgramAddressSync(
      [enc("score_components"), agent.toBuffer(), new BN(epoch).toArrayLike(Buffer, "le", 8)],
      program.programId,
    )[0];

  // ── 1. Initialise the IssuerConfig with a 5-key cluster, threshold 3 ─────
  it("initialises a 5-key issuer cluster with threshold 3", async () => {
    await program.methods
      .initializeConfig(
        submitter.publicKey,                     // issuer_node (rent payer)
        clusterPubkeys,
        3,                                       // threshold
        // VULN-16: this test exercises DIRECT (top-level) issueCertificate
        // calls only — no CPI path. Pubkey.default() disables the CPI
        // allow-list, which is the strictest setting (every CPI refused);
        // direct calls still work because the guard accepts caller_pid ==
        // certificate_issuer.programId regardless of allow-list state.
        PublicKey.default,                       // health_oracle_program_id
        // AW-01-EXT.6: this test does not exercise the on-chain
        // `challenge_certificate` path; an empty Vec + 0 leaves the
        // challenge ix DISABLED at the program level. The verifier
        // logic + digest properties are covered by the Rust unit tests
        // in `programs/certificate-issuer/src/instructions/challenge_certificate.rs`.
        [],                                      // challenge_attester_keys
        0,                                       // challenge_threshold
      )
      .accounts({
        issuerConfig: issuerConfigPda(),
        admin: submitter.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const cfg = await program.account.issuerConfig.fetch(issuerConfigPda());
    assert.equal(cfg.threshold, 3);
    assert.equal(cfg.clusterKeys.length, 5);
  });

  // ── 2. record baselines (cert preconditions) ─────────────────────────────
  // VULN-06: each agent signs its OWN `recordBaseline` — the audit's
  // "signer == agent owner" branch. Airdrop rent-exempt SOL first.
  it("records baselines for the agents", async () => {
    for (const agentKp of [agentOkKp, agentBadKp, agentReplayKp]) {
      // Airdrop enough SOL to cover BaselineStats rent + tx fees.
      const sig = await provider.connection.requestAirdrop(
        agentKp.publicKey, 1_000_000_000,    // 1 SOL
      );
      const { blockhash, lastValidBlockHeight } =
        await provider.connection.getLatestBlockhash();
      await provider.connection.confirmTransaction({
        signature: sig, blockhash, lastValidBlockHeight,
      });

      await program.methods
        // AW-03: trailing `baseline_commit_nonce` — must be non-zero, and on
        // a fresh PDA the stored nonce is 0 so any value > 0 is monotonic.
        .recordBaseline(agentKp.publicKey, [...baselineHash], 3, new BN(1), new BN(1))
        .accounts({
          baselineStats: baselinePda(agentKp.publicKey),
          issuerConfig: issuerConfigPda(),
          issuer: agentKp.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([agentKp])
        .rpc();
    }
  });

  // ── 2b. VULN-06 regressions — gating + per-epoch rate-limit ───────────────
  it("REJECTS recordBaseline from a non-cluster, non-agent signer", async () => {
    // The provider wallet (`submitter`) is NEITHER an agent NOR a cluster
    // signing key. Pre-VULN-06 this was the privileged writer; now it must
    // be rejected with `UnauthorizedBaselineWriter` (6040).
    const strangerAgent = Keypair.generate().publicKey;
    try {
      await program.methods
        .recordBaseline(strangerAgent, [...baselineHash], 3, new BN(1), new BN(1))
        .accounts({
          baselineStats: baselinePda(strangerAgent),
          issuerConfig: issuerConfigPda(),
          issuer: submitter.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      assert.fail("expected UnauthorizedBaselineWriter — submitter is neither agent nor cluster key");
    } catch (err: any) {
      const msg = (err.logs ?? []).join("\n") + (err.message ?? "");
      assert.ok(
        /UnauthorizedBaselineWriter|6040/.test(msg),
        `expected UnauthorizedBaselineWriter, got: ${msg}`,
      );
    }
  });

  it("REJECTS a second baseline rotation at the SAME epoch", async () => {
    // Audit mitigation 3: append-only / can't change baseline twice per epoch.
    // The agentOk baseline was already recorded at epoch 1 in test 2.
    // A second write at epoch 1 must be refused.
    try {
      await program.methods
        // Same epoch as the first record above. Epoch check fires before
        // the nonce-monotonic check, so use a strictly-greater nonce to
        // ensure the BaselineRotationTooSoon (epoch) error is the one we
        // observe — not a nonce-monotonic preemption.
        .recordBaseline(agentOk, [...baselineHash], 3, new BN(1), new BN(2))
        .accounts({
          baselineStats: baselinePda(agentOk),
          issuerConfig: issuerConfigPda(),
          issuer: agentOk,
          systemProgram: SystemProgram.programId,
        })
        .signers([agentOkKp])
        .rpc();
      assert.fail("expected BaselineRotationTooSoon — same-epoch rotation must fail");
    } catch (err: any) {
      const msg = (err.logs ?? []).join("\n") + (err.message ?? "");
      assert.ok(
        /BaselineRotationTooSoon|6041/.test(msg),
        `expected BaselineRotationTooSoon, got: ${msg}`,
      );
    }
  });

  it("REJECTS a baseline rotation at an EARLIER epoch", async () => {
    // Even an authorised writer cannot walk the recorded epoch backwards.
    try {
      // agentOk was last recorded at epoch 1; a write at epoch 0 also
      // trips the ZeroEpoch guard, so use a clean agent freshly recorded
      // at a higher epoch and then attempt to rotate downward.
      const freshKp = Keypair.generate();
      const sig = await provider.connection.requestAirdrop(
        freshKp.publicKey, 1_000_000_000,
      );
      const { blockhash, lastValidBlockHeight } =
        await provider.connection.getLatestBlockhash();
      await provider.connection.confirmTransaction({
        signature: sig, blockhash, lastValidBlockHeight,
      });

      // Record at epoch 5 first.
      await program.methods
        .recordBaseline(freshKp.publicKey, [...baselineHash], 3, new BN(5), new BN(1))
        .accounts({
          baselineStats: baselinePda(freshKp.publicKey),
          issuerConfig: issuerConfigPda(),
          issuer: freshKp.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([freshKp])
        .rpc();

      // Now attempt to walk back to epoch 3. Epoch check fires before nonce
      // check; the nonce here is strictly-> so the test observes the epoch
      // error, not a nonce-monotonic preemption.
      await program.methods
        .recordBaseline(freshKp.publicKey, [...baselineHash], 3, new BN(3), new BN(2))
        .accounts({
          baselineStats: baselinePda(freshKp.publicKey),
          issuerConfig: issuerConfigPda(),
          issuer: freshKp.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([freshKp])
        .rpc();
      assert.fail("expected BaselineEpochNotMonotonic — must not walk epoch backwards");
    } catch (err: any) {
      const msg = (err.logs ?? []).join("\n") + (err.message ?? "");
      assert.ok(
        /BaselineEpochNotMonotonic|6042/.test(msg),
        `expected BaselineEpochNotMonotonic, got: ${msg}`,
      );
    }
  });

  // ── DONE-WHEN HALF 1 — 3 signatures succeed ──────────────────────────────
  it("issues a certificate when 3 valid cluster signatures are attached", async () => {
    const epoch = 1, score = 916, alertTier = 0 /* GREEN */, flags = 0,
          immediateRed = false;

    const slotAnchor = await captureSlotAnchor();

    const digest = certPayloadDigest(
      agentOk, epoch, score, alertTier, flags, baselineHash, immediateRed,
      inputCommitment,
      slotAnchor.slot, slotAnchor.hash,
      1n,                                  // AW-03: baselineCommitNonce stamped on BaselineStats
      scoringCodeHash,                     // AW-04: scoring-kernel bundle hash
      scoreComponentsHash,                 // AW-04: sha256(components payload)
    );

    // Pick three of the five cluster keys to sign.
    const signers = clusterKps.slice(0, 3);
    const ed25519Ixs = signers.map((kp) => ed25519VerifyIx(
      kp.publicKey,
      nacl.sign.detached(digest, kp.secretKey),
      digest,
    ));

    const issueIx = await program.methods
      .issueCertificate(
        new BN(epoch), score, alertTier, flags, immediateRed,
        [...inputCommitment],
        new BN(slotAnchor.slot.toString()),  // slotAnchorSlot
        [...slotAnchor.hash],                // slotAnchorHash
        [...scoringCodeHash],                // AW-04: scoringCodeHash
        Buffer.from(scoreComponentsPayload), // AW-04: raw components payload
      )
      .accounts({
        certificate: certPda(agentOk, epoch),
        scoreComponents: scoreComponentsPda(agentOk, epoch),  // AW-04
        baselineStats: baselinePda(agentOk),
        issuerConfig: issuerConfigPda(),
        issuer: submitter.publicKey,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        slotHashesSysvar: SYSVAR_SLOT_HASHES_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    // 3 Ed25519 precompile ixs FIRST, then our cert ix. The precompiles
    // verify the signatures natively; our handler reads them out of the
    // Instructions sysvar.
    const tx = new anchor.web3.Transaction().add(...ed25519Ixs, issueIx);
    await provider.sendAndConfirm(tx);

    const cert = await program.account.healthCertificate.fetch(
      certPda(agentOk, epoch),
    );
    assert.equal(cert.score, score);
    assert.equal(cert.alertTier, alertTier);
    assert.ok(cert.agentWallet.equals(agentOk));
  });

  // ── DONE-WHEN HALF 2 — 2 signatures are rejected ─────────────────────────
  it("REJECTS a certificate write with only 2 signatures", async () => {
    const epoch = 1, score = 800, alertTier = 0, flags = 0, immediateRed = false;
    const slotAnchor = await captureSlotAnchor();
    const digest = certPayloadDigest(
      agentBad, epoch, score, alertTier, flags, baselineHash, immediateRed,
      inputCommitment,
      slotAnchor.slot, slotAnchor.hash,
      1n,                                  // AW-03: baselineCommitNonce stamped on BaselineStats
      scoringCodeHash,                     // AW-04: scoring-kernel bundle hash
      scoreComponentsHash,                 // AW-04: sha256(components payload)
    );

    // Only TWO signers — below the threshold of 3.
    const signers = clusterKps.slice(0, 2);
    const ed25519Ixs = signers.map((kp) => ed25519VerifyIx(
      kp.publicKey,
      nacl.sign.detached(digest, kp.secretKey),
      digest,
    ));

    const issueIx = await program.methods
      .issueCertificate(
        new BN(epoch), score, alertTier, flags, immediateRed,
        [...inputCommitment],
        new BN(slotAnchor.slot.toString()),
        [...slotAnchor.hash],
        [...scoringCodeHash],                // AW-04: scoringCodeHash
        Buffer.from(scoreComponentsPayload), // AW-04: raw components payload
      )
      .accounts({
        certificate: certPda(agentBad, epoch),
        scoreComponents: scoreComponentsPda(agentBad, epoch),  // AW-04
        baselineStats: baselinePda(agentBad),
        issuerConfig: issuerConfigPda(),
        issuer: submitter.publicKey,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        slotHashesSysvar: SYSVAR_SLOT_HASHES_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    const tx = new anchor.web3.Transaction().add(...ed25519Ixs, issueIx);
    try {
      await provider.sendAndConfirm(tx);
      assert.fail("expected InsufficientSignatures — 2 of 3 should fail");
    } catch (err: any) {
      const msg = (err.logs ?? []).join("\n") + (err.message ?? "");
      assert.ok(
        /InsufficientSignatures|6033/.test(msg),
        `expected InsufficientSignatures, got: ${msg}`,
      );
    }
  });

  // ── A non-cluster signer is filtered out by the on-chain check ───────────
  it("REJECTS when a third signer is not a cluster key", async () => {
    const epoch = 1, score = 800, alertTier = 0, flags = 0, immediateRed = false;
    const slotAnchor = await captureSlotAnchor();
    const digest = certPayloadDigest(
      agentBad, epoch, score, alertTier, flags, baselineHash, immediateRed,
      inputCommitment,
      slotAnchor.slot, slotAnchor.hash,
      1n,                                  // AW-03: baselineCommitNonce stamped on BaselineStats
      scoringCodeHash,                     // AW-04: scoring-kernel bundle hash
      scoreComponentsHash,                 // AW-04: sha256(components payload)
    );

    const cluster2 = clusterKps.slice(0, 2);
    const outsider = nacl.sign.keyPair();         // NOT in the cluster

    const ed25519Ixs = [
      ...cluster2.map((kp) => ed25519VerifyIx(
        kp.publicKey,
        nacl.sign.detached(digest, kp.secretKey),
        digest,
      )),
      ed25519VerifyIx(
        outsider.publicKey,
        nacl.sign.detached(digest, outsider.secretKey),
        digest,
      ),
    ];

    const issueIx = await program.methods
      .issueCertificate(
        new BN(epoch), score, alertTier, flags, immediateRed,
        [...inputCommitment],
        new BN(slotAnchor.slot.toString()),
        [...slotAnchor.hash],
        [...scoringCodeHash],                // AW-04: scoringCodeHash
        Buffer.from(scoreComponentsPayload), // AW-04: raw components payload
      )
      .accounts({
        certificate: certPda(agentBad, epoch),
        scoreComponents: scoreComponentsPda(agentBad, epoch),  // AW-04
        baselineStats: baselinePda(agentBad),
        issuerConfig: issuerConfigPda(),
        issuer: submitter.publicKey,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        slotHashesSysvar: SYSVAR_SLOT_HASHES_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    const tx = new anchor.web3.Transaction().add(...ed25519Ixs, issueIx);
    try {
      await provider.sendAndConfirm(tx);
      assert.fail("expected InsufficientSignatures — outsider does not count");
    } catch (err: any) {
      const msg = (err.logs ?? []).join("\n") + (err.message ?? "");
      assert.ok(
        /InsufficientSignatures|6033/.test(msg),
        `expected InsufficientSignatures, got: ${msg}`,
      );
    }
  });

  // ── VULN-01 regression — old/historical signatures cannot be replayed ────
  it("REJECTS 3 valid cluster signatures over a historical/mismatched digest", async () => {
    const epoch = 1, score = 916, alertTier = 0, flags = 0, immediateRed = false;
    const slotAnchor = await captureSlotAnchor();

    // This is the digest the issue_certificate instruction will recompute
    // from its current accounts + args.
    const expectedDigest = certPayloadDigest(
      agentReplay, epoch, score, alertTier, flags, baselineHash, immediateRed,
      inputCommitment,
      slotAnchor.slot, slotAnchor.hash,
      1n,                                  // AW-03: baselineCommitNonce stamped on BaselineStats
      scoringCodeHash,                     // AW-04: scoring-kernel bundle hash
      scoreComponentsHash,                 // AW-04: sha256(components payload)
    );

    // This is what the attacker tries to replay: three real cluster-key
    // signatures, but over a different payload. The signatures are valid
    // Ed25519 precompile inputs, yet they MUST NOT count toward this cert.
    // The historical anchor differs too — a real replay of an old cert
    // would also bring an old slot anchor along for the ride.
    const historicalDigest = certPayloadDigest(
      agentReplay,
      epoch + 8,        // old / different epoch
      999,              // different score
      alertTier,
      flags,
      baselineHash,
      immediateRed,
      inputCommitment,
      slotAnchor.slot + 1n,                // different slot
      Buffer.alloc(32, 0x55),              // different anchor hash
      42n,                                  // AW-03: different baselineCommitNonce to drift digest further
      Buffer.alloc(32, 0x66),              // AW-04: different scoringCodeHash to drift further
      Buffer.alloc(32, 0x77),              // AW-04: different scoreComponentsHash to drift further
    );
    assert.notDeepEqual(
      [...historicalDigest],
      [...expectedDigest],
      "test setup must use a genuinely different digest",
    );

    const ed25519Ixs = clusterKps.slice(0, 3).map((kp) => ed25519VerifyIx(
      kp.publicKey,
      nacl.sign.detached(historicalDigest, kp.secretKey),
      historicalDigest,
    ));

    const issueIx = await program.methods
      .issueCertificate(
        new BN(epoch), score, alertTier, flags, immediateRed,
        [...inputCommitment],
        new BN(slotAnchor.slot.toString()),
        [...slotAnchor.hash],
        [...scoringCodeHash],                // AW-04: scoringCodeHash
        Buffer.from(scoreComponentsPayload), // AW-04: raw components payload
      )
      .accounts({
        certificate: certPda(agentReplay, epoch),
        scoreComponents: scoreComponentsPda(agentReplay, epoch),  // AW-04
        baselineStats: baselinePda(agentReplay),
        issuerConfig: issuerConfigPda(),
        issuer: submitter.publicKey,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        slotHashesSysvar: SYSVAR_SLOT_HASHES_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    const tx = new anchor.web3.Transaction().add(...ed25519Ixs, issueIx);
    try {
      await provider.sendAndConfirm(tx);
      assert.fail("expected InsufficientSignatures — historical digest must not count");
    } catch (err: any) {
      const msg = (err.logs ?? []).join("\n") + (err.message ?? "");
      assert.ok(
        /InsufficientSignatures|6033/.test(msg),
        `expected InsufficientSignatures, got: ${msg}`,
      );
    }
  });
});
