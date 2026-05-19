// =============================================================================
// Day 19 — health_oracle.submit_score CPI + epoch history.
//
// This is the missing done-when pin:
//   health_oracle.submit_score -> CPI -> certificate_issuer.issue_certificate
//   epoch 1 certificate persists
//   advance epoch
//   epoch 2 certificate is written to a distinct PDA
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import BN from "bn.js";
import {
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
} from "@solana/web3.js";
import { assert } from "chai";

const healthOracle = anchor.workspace.HealthOracle as anchor.Program<any>;
const certificateIssuer = anchor.workspace.CertificateIssuer as anchor.Program<any>;

const SHARED_ORACLE = Keypair.fromSeed(Buffer.alloc(32, 19));

function agentPda(agent: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("agent"), agent.toBuffer()],
    healthOracle.programId,
  )[0];
}

function escrowPda(agent: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("escrow"), agent.toBuffer()],
    healthOracle.programId,
  )[0];
}

function oracleConfigPda(): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("oracle_config")],
    healthOracle.programId,
  )[0];
}

function epochStatePda(): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("epoch_state")],
    healthOracle.programId,
  )[0];
}

function issuerConfigPda(): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("issuer_config")],
    certificateIssuer.programId,
  )[0];
}

function baselinePda(agent: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("baseline"), agent.toBuffer()],
    certificateIssuer.programId,
  )[0];
}

function certificatePda(agent: PublicKey, epoch: BN): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("cert"), agent.toBuffer(), epoch.toArrayLike(Buffer, "le", 8)],
    certificateIssuer.programId,
  )[0];
}

async function airdrop(conn: anchor.web3.Connection, pk: PublicKey, sol = 1) {
  const sig = await conn.requestAirdrop(pk, sol * LAMPORTS_PER_SOL);
  const bh = await conn.getLatestBlockhash();
  await conn.confirmTransaction({ signature: sig, ...bh }, "confirmed");
}

async function maybe<T>(fn: () => Promise<T>): Promise<T | null> {
  try {
    return await fn();
  } catch {
    return null;
  }
}

async function ensureIssuerConfig(provider: anchor.AnchorProvider) {
  const config = issuerConfigPda();
  const existing = await maybe(() => certificateIssuer.account.issuerConfig.fetch(config));
  if (existing) {
    assert.equal(existing.issuerNode.toBase58(), SHARED_ORACLE.publicKey.toBase58());
    return config;
  }

  await certificateIssuer.methods
    .initializeConfig(SHARED_ORACLE.publicKey)
    .accounts({
      issuerConfig: config,
      admin: provider.wallet.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .rpc({ commitment: "confirmed" });
  return config;
}

async function ensureOracleConfig(provider: anchor.AnchorProvider) {
  const config = oracleConfigPda();
  const existing = await maybe(() => healthOracle.account.oracleConfig.fetch(config));
  if (existing) {
    assert.equal(existing.oracleKey.toBase58(), SHARED_ORACLE.publicKey.toBase58());
    return config;
  }

  await healthOracle.methods
    .initializeOracleConfig({
      oracleKey: SHARED_ORACLE.publicKey,
      adminKey: provider.wallet.publicKey,
    })
    .accounts({
      deployer: provider.wallet.publicKey,
      oracleConfig: config,
      systemProgram: SystemProgram.programId,
    })
    .rpc({ commitment: "confirmed" });
  return config;
}

async function ensureEpochState(provider: anchor.AnchorProvider, oracleConfig: PublicKey) {
  const epochState = epochStatePda();
  const existing = await maybe(() => healthOracle.account.epochState.fetch(epochState));
  if (existing) return epochState;

  await healthOracle.methods
    .initializeEpoch(new BN(1))
    .accounts({
      epochState,
      oracleConfig,
      admin: provider.wallet.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .rpc({ commitment: "confirmed" });
  return epochState;
}

async function waitForTestEpoch() {
  await new Promise((resolve) => setTimeout(resolve, 1_100));
}

describe("Day 19 — CPI score submission + epoch history", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const conn = provider.connection;

  it("writes epoch-keyed certificates through health_oracle CPI", async () => {
    await airdrop(conn, SHARED_ORACLE.publicKey, 4);

    const owner = Keypair.generate();
    const agent = Keypair.generate();
    await airdrop(conn, owner.publicKey, 2);

    const oracleConfig = await ensureOracleConfig(provider);
    const issuerConfig = await ensureIssuerConfig(provider);
    const epochState = await ensureEpochState(provider, oracleConfig);

    const agentRegistration = agentPda(agent.publicKey);
    const escrowVault = escrowPda(agent.publicKey);

    await healthOracle.methods
      .registerAgent({ name: "Day19CpiAgent" })
      .accounts({
        owner: owner.publicKey,
        agentWallet: agent.publicKey,
        agentRegistration,
        escrowVault,
        systemProgram: SystemProgram.programId,
      })
      .signers([owner, agent])
      .rpc({ commitment: "confirmed" });

    const baselineHash = Array.from(Buffer.alloc(32, 19));
    await healthOracle.methods
      .commitBaseline({
        baselineHash,
        baselineAlgoVersion: 3,
        commitNonce: new BN(1),
        committerKind: { oracle: {} },
      })
      .accounts({
        agentRegistration,
        oracleConfig,
        signer: SHARED_ORACLE.publicKey,
      })
      .signers([SHARED_ORACLE])
      .rpc({ commitment: "confirmed" });

    const baseline = baselinePda(agent.publicKey);
    await certificateIssuer.methods
      .recordBaseline(agent.publicKey, baselineHash, 3, new BN(1))
      .accounts({
        baselineStats: baseline,
        issuerConfig,
        issuer: SHARED_ORACLE.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([SHARED_ORACLE])
      .rpc({ commitment: "confirmed" });

    const epoch1 = new BN(1);
    const cert1 = certificatePda(agent.publicKey, epoch1);
    await healthOracle.methods
      .submitScore(epoch1, 850, 0, 0x11, false)
      .accounts({
        agentRegistration,
        oracleConfig,
        epochState,
        oracle: SHARED_ORACLE.publicKey,
        certificate: cert1,
        baselineStats: baseline,
        issuerConfig,
        certificateIssuerProgram: certificateIssuer.programId,
        systemProgram: SystemProgram.programId,
      })
      .signers([SHARED_ORACLE])
      .rpc({ commitment: "confirmed" });

    const cert1Account = await certificateIssuer.account.healthCertificate.fetch(cert1);
    assert.equal(cert1Account.agentWallet.toBase58(), agent.publicKey.toBase58());
    assert.equal(cert1Account.epoch.toNumber(), 1);
    assert.equal(cert1Account.score, 850);
    assert.equal(cert1Account.flags, 0x11);
    assert.deepEqual(Array.from(cert1Account.baselineHash), baselineHash);

    await waitForTestEpoch();
    await healthOracle.methods
      .advanceEpoch()
      .accounts({
        epochState,
        advancer: SHARED_ORACLE.publicKey,
      })
      .signers([SHARED_ORACLE])
      .rpc({ commitment: "confirmed" });

    const stateAfterAdvance = await healthOracle.account.epochState.fetch(epochState);
    assert.equal(stateAfterAdvance.currentEpoch.toNumber(), 2);

    const cert2 = certificatePda(agent.publicKey, new BN(2));
    await healthOracle.methods
      .submitScore(new BN(2), 320, 2, 0x22, true)
      .accounts({
        agentRegistration,
        oracleConfig,
        epochState,
        oracle: SHARED_ORACLE.publicKey,
        certificate: cert2,
        baselineStats: baseline,
        issuerConfig,
        certificateIssuerProgram: certificateIssuer.programId,
        systemProgram: SystemProgram.programId,
      })
      .signers([SHARED_ORACLE])
      .rpc({ commitment: "confirmed" });

    const [epoch1StillThere, epoch2Account] = await Promise.all([
      certificateIssuer.account.healthCertificate.fetch(cert1),
      certificateIssuer.account.healthCertificate.fetch(cert2),
    ]);

    assert.equal(epoch1StillThere.epoch.toNumber(), 1);
    assert.equal(epoch1StillThere.score, 850);
    assert.equal(epoch2Account.epoch.toNumber(), 2);
    assert.equal(epoch2Account.score, 320);
    assert.isTrue(epoch2Account.immediateRed);
    assert.notEqual(cert1.toBase58(), cert2.toBase58());
  });
});
