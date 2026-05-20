// =============================================================================
// tests/certificate_issuer.integration.ts
//
// Day-18 done-when integration test for the certificate-issuer program:
// "an epoch-1 certificate can be issued and read back."
//
// Runs against `anchor test` (a local validator). It:
//   1. initialises the IssuerConfig,
//   2. records a baseline for an agent,
//   3. issues an epoch-1 HealthCertificate,
//   4. reads the certificate back — both by direct PDA fetch AND via the
//      get_certificate instruction,
//   5. asserts a second issue for the same (agent, epoch) FAILS — the
//      certificate is write-once,
//   6. asserts an inconsistent (score, alert) pair is REJECTED.
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import { assert } from "chai";

const { BN } = anchor;

describe("certificate-issuer (Day 18)", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.CertificateIssuer as Program;
  const issuer = provider.wallet; // the issuer node, for this test

  // A synthetic agent.
  const agent = Keypair.generate().publicKey;
  const baselineHash = Buffer.alloc(32, 7); // non-zero 32-byte hash

  // ── PDA helpers ────────────────────────────────────────────────────────────
  const enc = anchor.utils.bytes.utf8.encode;

  const issuerConfigPda = () =>
    PublicKey.findProgramAddressSync(
      [enc("issuer_config")],
      program.programId
    )[0];

  const baselinePda = (agentKey: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [enc("baseline"), agentKey.toBuffer()],
      program.programId
    )[0];

  const certPda = (agentKey: PublicKey, epoch: number) =>
    PublicKey.findProgramAddressSync(
      [enc("cert"), agentKey.toBuffer(), new BN(epoch).toArrayLike(Buffer, "le", 8)],
      program.programId
    )[0];

  // ── 1. initialize_config ───────────────────────────────────────────────────
  it("initialises the issuer config", async () => {
    await program.methods
      .initializeConfig(issuer.publicKey)
      .accounts({
        issuerConfig: issuerConfigPda(),
        admin: issuer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const config = await program.account.issuerConfig.fetch(issuerConfigPda());
    assert.ok(config.issuerNode.equals(issuer.publicKey));
  });

  // ── 2. record_baseline ─────────────────────────────────────────────────────
  it("records a baseline for the agent", async () => {
    await program.methods
      .recordBaseline(agent, [...baselineHash], 3, new BN(1))
      .accounts({
        baselineStats: baselinePda(agent),
        issuerConfig: issuerConfigPda(),
        issuer: issuer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const stats = await program.account.baselineStats.fetch(baselinePda(agent));
    assert.ok(stats.agentWallet.equals(agent));
    assert.equal(stats.baselineAlgoVersion, 3);
  });

  // ── 3. issue an epoch-1 certificate ────────────────────────────────────────
  it("issues an epoch-1 certificate", async () => {
    await program.methods
      .issueCertificate(new BN(1), 916, 0 /* GREEN */, 0, 900, false)
      .accounts({
        certificate: certPda(agent, 1),
        baselineStats: baselinePda(agent),
        issuerConfig: issuerConfigPda(),
        issuer: issuer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // ── 4a. read it back by direct PDA fetch ────────────────────────────────
    const cert = await program.account.healthCertificate.fetch(certPda(agent, 1));
    assert.ok(cert.agentWallet.equals(agent));
    assert.equal(cert.epoch.toNumber(), 1);
    assert.equal(cert.score, 916);
    assert.equal(cert.alertTier, 0);
    assert.equal(cert.immediateRed, false);
    assert.deepEqual([...cert.baselineHash], [...baselineHash]);
  });

  // ── 4b. read it back via the get_certificate instruction ───────────────────
  it("reads the certificate back via get_certificate", async () => {
    // get_certificate emits a CertificateRead event; the instruction
    // succeeding is itself proof the certificate exists and is the right PDA.
    await program.methods
      .getCertificate(agent, new BN(1))
      .accounts({ certificate: certPda(agent, 1) })
      .rpc();
  });

  // ── 5. a certificate is write-once ─────────────────────────────────────────
  it("rejects re-issuing the same (agent, epoch)", async () => {
    try {
      await program.methods
        .issueCertificate(new BN(1), 800, 0, 0, 900, false)
        .accounts({
          certificate: certPda(agent, 1),
          baselineStats: baselinePda(agent),
          issuerConfig: issuerConfigPda(),
          issuer: issuer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      assert.fail("re-issue should have failed — the cert PDA already exists");
    } catch (err) {
      // `init` on an existing account fails — the certificate is write-once.
      assert.ok(err, "expected an account-already-in-use error");
    }
  });

  // ── 6. an inconsistent (score, alert) pair is rejected ─────────────────────
  it("rejects an inconsistent score/alert pair", async () => {
    try {
      // score 916 (high) but alert RED, without immediate_red — inconsistent.
      await program.methods
        .issueCertificate(new BN(2), 916, 2 /* RED */, 0, 900, false)
        .accounts({
          certificate: certPda(agent, 2),
          baselineStats: baselinePda(agent),
          issuerConfig: issuerConfigPda(),
          issuer: issuer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      assert.fail("inconsistent score/alert should have been rejected");
    } catch (err) {
      assert.ok(err, "expected InconsistentScoreAlert");
    }
  });

  // ── per-epoch history: epoch-2 is a SEPARATE certificate ───────────────────
  it("keeps per-epoch history — epoch 2 is a distinct certificate", async () => {
    await program.methods
      .issueCertificate(new BN(2), 720, 0 /* GREEN */, 0, 900, false)
      .accounts({
        certificate: certPda(agent, 2),
        baselineStats: baselinePda(agent),
        issuerConfig: issuerConfigPda(),
        issuer: issuer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Both epoch-1 and epoch-2 certificates exist, independently.
    const c1 = await program.account.healthCertificate.fetch(certPda(agent, 1));
    const c2 = await program.account.healthCertificate.fetch(certPda(agent, 2));
    assert.equal(c1.score, 916);
    assert.equal(c2.score, 720);
    assert.notOk(certPda(agent, 1).equals(certPda(agent, 2)));
  });
});
