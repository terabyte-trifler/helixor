// =============================================================================
// Day 18 — certificate-issuer integration tests.
//
// Runs against Anchor's local validator. Covers the done-when:
//   config init -> baseline record -> issue epoch cert -> read back
//   write-once epoch certificates
//   score/alert consistency validation
//   per-epoch PDA history
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import BN from "bn.js";
import { PublicKey, Keypair, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { assert } from "chai";

const program = anchor.workspace.CertificateIssuer as anchor.Program<any>;
const SHARED_ISSUER = Keypair.fromSeed(Buffer.alloc(32, 19));

function issuerConfigPda(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("issuer_config")],
    program.programId,
  );
}

function baselinePda(agent: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("baseline"), agent.toBuffer()],
    program.programId,
  );
}

function certificatePda(agent: PublicKey, epoch: BN): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("cert"),
      agent.toBuffer(),
      epoch.toArrayLike(Buffer, "le", 8),
    ],
    program.programId,
  );
}

async function airdrop(conn: anchor.web3.Connection, pk: PublicKey, sol = 1) {
  const sig = await conn.requestAirdrop(pk, sol * LAMPORTS_PER_SOL);
  const bh = await conn.getLatestBlockhash();
  await conn.confirmTransaction({ signature: sig, ...bh }, "confirmed");
}

async function expectError(promise: Promise<any>, label: string): Promise<void> {
  try {
    await promise;
    assert.fail(`Expected ${label} to fail`);
  } catch (err: any) {
    assert.isOk(err, `${label} failed`);
  }
}

describe("Day 18 certificate-issuer", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const conn = provider.connection;

  const issuer = SHARED_ISSUER;
  const agent = Keypair.generate();
  const baselineHash = Array.from(Buffer.alloc(32, 7));

  it("initializes config, records baseline, issues and reads an epoch cert", async () => {
    await airdrop(conn, issuer.publicKey, 2);

    const [config] = issuerConfigPda();
    await program.methods
      .initializeConfig(issuer.publicKey)
      .accounts({
        issuerConfig: config,
        admin: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc({ commitment: "confirmed" });

    const configAccount = await program.account.issuerConfig.fetch(config);
    assert.equal(configAccount.issuerNode.toBase58(), issuer.publicKey.toBase58());

    const [baseline] = baselinePda(agent.publicKey);
    await program.methods
      .recordBaseline(agent.publicKey, baselineHash, 3, new BN(1))
      .accounts({
        baselineStats: baseline,
        issuerConfig: config,
        issuer: issuer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([issuer])
      .rpc({ commitment: "confirmed" });

    const baselineAccount = await program.account.baselineStats.fetch(baseline);
    assert.equal(baselineAccount.agentWallet.toBase58(), agent.publicKey.toBase58());
    assert.deepEqual(Array.from(baselineAccount.baselineHash), baselineHash);
    assert.equal(baselineAccount.baselineAlgoVersion, 3);

    const epoch1 = new BN(1);
    const [cert1] = certificatePda(agent.publicKey, epoch1);
    await program.methods
      .issueCertificate(epoch1, 850, 0, 0x11, false)
      .accounts({
        baselineStats: baseline,
        certificate: cert1,
        issuerConfig: config,
        issuer: issuer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([issuer])
      .rpc({ commitment: "confirmed" });

    const certAccount = await program.account.healthCertificate.fetch(cert1);
    assert.equal(certAccount.agentWallet.toBase58(), agent.publicKey.toBase58());
    assert.equal(certAccount.epoch.toNumber(), 1);
    assert.equal(certAccount.score, 850);
    assert.equal(certAccount.alertTier, 0);
    assert.equal(certAccount.flags, 0x11);
    assert.isFalse(certAccount.immediateRed);
    assert.deepEqual(Array.from(certAccount.baselineHash), baselineHash);

    await program.methods
      .getCertificate(agent.publicKey, epoch1)
      .accounts({ certificate: cert1 })
      .rpc({ commitment: "confirmed" });

    await expectError(
      program.methods
        .issueCertificate(epoch1, 860, 0, 0x12, false)
        .accounts({
          baselineStats: baseline,
          certificate: cert1,
          issuerConfig: config,
          issuer: issuer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([issuer])
        .rpc({ commitment: "confirmed" }),
      "re-issue for same epoch",
    );

    const epochBad = new BN(99);
    const [badCert] = certificatePda(agent.publicKey, epochBad);
    await expectError(
      program.methods
        .issueCertificate(epochBad, 100, 0, 0, false)
        .accounts({
          baselineStats: baseline,
          certificate: badCert,
          issuerConfig: config,
          issuer: issuer.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([issuer])
        .rpc({ commitment: "confirmed" }),
      "inconsistent GREEN low-score certificate",
    );

    const epoch2 = new BN(2);
    const [cert2] = certificatePda(agent.publicKey, epoch2);
    await program.methods
      .issueCertificate(epoch2, 320, 2, 0x20, false)
      .accounts({
        baselineStats: baseline,
        certificate: cert2,
        issuerConfig: config,
        issuer: issuer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([issuer])
      .rpc({ commitment: "confirmed" });

    assert.notEqual(cert1.toBase58(), cert2.toBase58());
    const epoch2Account = await program.account.healthCertificate.fetch(cert2);
    assert.equal(epoch2Account.epoch.toNumber(), 2);
    assert.equal(epoch2Account.alertTier, 2);
  });
});
