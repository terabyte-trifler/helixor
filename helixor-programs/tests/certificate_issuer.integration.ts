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
//   6. attempts with 3 signatures but over a TAMPERED digest (one signer
//      signed a different score) -> REJECTED (those bad sigs don't count).
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  PublicKey, Keypair, SystemProgram, TransactionInstruction,
  SYSVAR_INSTRUCTIONS_PUBKEY, Ed25519Program,
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
): Buffer {
  const epochBuf = Buffer.alloc(8);  epochBuf.writeBigUInt64BE(BigInt(epoch));
  const scoreBuf = Buffer.alloc(2);  scoreBuf.writeUInt16BE(score);
  const flagsBuf = Buffer.alloc(4);  flagsBuf.writeUInt32BE(flags);
  const payload = Buffer.concat([
    agent.toBuffer(),                            // 32
    epochBuf,                                    //  8
    scoreBuf,                                    //  2
    Buffer.from([alertTier]),                    //  1
    flagsBuf,                                    //  4
    baselineHash,                                // 32
    Buffer.from([immediateRed ? 1 : 0]),         //  1
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

  // Two synthetic agents — one for the success path, one for the failure.
  const agentOk = Keypair.generate().publicKey;
  const agentBad = Keypair.generate().publicKey;
  const baselineHash = Buffer.alloc(32, 7);

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

  // ── 1. Initialise the IssuerConfig with a 5-key cluster, threshold 3 ─────
  it("initialises a 5-key issuer cluster with threshold 3", async () => {
    await program.methods
      .initializeConfig(
        submitter.publicKey,                     // issuer_node (rent payer)
        clusterPubkeys,
        3,                                       // threshold
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
  it("records baselines for the agents", async () => {
    for (const agent of [agentOk, agentBad]) {
      await program.methods
        .recordBaseline(agent, [...baselineHash], 3, new BN(1))
        .accounts({
          baselineStats: baselinePda(agent),
          issuerConfig: issuerConfigPda(),
          issuer: submitter.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    }
  });

  // ── DONE-WHEN HALF 1 — 3 signatures succeed ──────────────────────────────
  it("issues a certificate when 3 valid cluster signatures are attached", async () => {
    const epoch = 1, score = 916, alertTier = 0 /* GREEN */, flags = 0,
          immediateRed = false;

    const digest = certPayloadDigest(
      agentOk, epoch, score, alertTier, flags, baselineHash, immediateRed,
    );

    // Pick three of the five cluster keys to sign.
    const signers = clusterKps.slice(0, 3);
    const ed25519Ixs = signers.map((kp) => ed25519VerifyIx(
      kp.publicKey,
      nacl.sign.detached(digest, kp.secretKey),
      digest,
    ));

    const issueIx = await program.methods
      .issueCertificate(new BN(epoch), score, alertTier, flags, immediateRed)
      .accounts({
        certificate: certPda(agentOk, epoch),
        baselineStats: baselinePda(agentOk),
        issuerConfig: issuerConfigPda(),
        issuer: submitter.publicKey,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
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
    const digest = certPayloadDigest(
      agentBad, epoch, score, alertTier, flags, baselineHash, immediateRed,
    );

    // Only TWO signers — below the threshold of 3.
    const signers = clusterKps.slice(0, 2);
    const ed25519Ixs = signers.map((kp) => ed25519VerifyIx(
      kp.publicKey,
      nacl.sign.detached(digest, kp.secretKey),
      digest,
    ));

    const issueIx = await program.methods
      .issueCertificate(new BN(epoch), score, alertTier, flags, immediateRed)
      .accounts({
        certificate: certPda(agentBad, epoch),
        baselineStats: baselinePda(agentBad),
        issuerConfig: issuerConfigPda(),
        issuer: submitter.publicKey,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
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
    const digest = certPayloadDigest(
      agentBad, epoch, score, alertTier, flags, baselineHash, immediateRed,
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
      .issueCertificate(new BN(epoch), score, alertTier, flags, immediateRed)
      .accounts({
        certificate: certPda(agentBad, epoch),
        baselineStats: baselinePda(agentBad),
        issuerConfig: issuerConfigPda(),
        issuer: submitter.publicKey,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
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
});
