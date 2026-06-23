// =============================================================================
// tests/cpi_epoch.integration.ts
//
// Day-19 done-when integration test, against `anchor test` (local validator):
//
//   1. the oracle pipeline writes an epoch-keyed certificate VIA CPI
//      (health_oracle.submit_score -> certificate_issuer.issue_certificate),
//   2. epoch history is queryable on-chain — epoch 1 and epoch 2 are
//      distinct, both readable,
//   3. get_health reads the latest (current-epoch) certificate.
//
// Prerequisites assumed already run by earlier setup (or run here):
// the agent is registered + baseline-committed on health_oracle, and the
// certificate-issuer config + baseline are recorded.
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  PublicKey, Keypair, SystemProgram, SYSVAR_SLOT_HASHES_PUBKEY,
} from "@solana/web3.js";
import { assert } from "chai";

const { BN } = anchor;
const enc = anchor.utils.bytes.utf8.encode;

describe("health-oracle <-> certificate-issuer CPI (Day 19)", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const oracleProgram = anchor.workspace.HealthOracle as Program;
  const certProgram = anchor.workspace.CertificateIssuer as Program;
  const oracle = provider.wallet; // oracle node = issuer node, for this test

  const agent = Keypair.generate().publicKey;
  const baselineHash = Buffer.alloc(32, 9);
  // AW-01: fixed test input-provenance commitment for the CPI path.
  const inputCommitment = Buffer.alloc(32, 0x55);

  // ── PDA helpers ────────────────────────────────────────────────────────────
  const epochStatePda = () =>
    PublicKey.findProgramAddressSync(
      [enc("epoch_state")],
      oracleProgram.programId
    )[0];

  const certPda = (epoch: number) =>
    PublicKey.findProgramAddressSync(
      [
        enc("cert"),
        agent.toBuffer(),
        new BN(epoch).toArrayLike(Buffer, "le", 8),
      ],
      certProgram.programId
    )[0];

  const baselinePda = () =>
    PublicKey.findProgramAddressSync(
      [enc("baseline"), agent.toBuffer()],
      certProgram.programId
    )[0];

  const issuerConfigPda = () =>
    PublicKey.findProgramAddressSync(
      [enc("issuer_config")],
      certProgram.programId
    )[0];

  // AW-01-EXT — capture a LIVE `(slot, block_hash)` from the validator.
  // The on-chain `verify_slot_anchor` walks SlotHashes and refuses
  // anything outside the ~512-slot window, so the anchor must be fresh.
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

  // ── 1. submit_score writes the certificate by CPI ──────────────────────────
  it("writes an epoch-1 certificate via CPI from health_oracle", async () => {
    // Read the current epoch (1, freshly initialised).
    const epochState: any = await oracleProgram.account.epochState.fetch(
      epochStatePda()
    );
    const epoch = epochState.currentEpoch.toNumber();
    assert.equal(epoch, 1);

    const slotAnchor = await captureSlotAnchor();

    // submit_score on health_oracle — internally CPIs issue_certificate.
    await oracleProgram.methods
      .submitScore(
        new BN(epoch), 916, 0 /* GREEN */, 0, false,
        [...inputCommitment],            // AW-01
        new BN(slotAnchor.slot.toString()),   // AW-01-EXT slot
        [...slotAnchor.hash],                 // AW-01-EXT block hash
        [...Buffer.alloc(32, 0xab)],          // AW-04: scoringCodeHash (non-zero)
        Buffer.from(JSON.stringify({ v: 1 })),// AW-04: scoreComponentsPayload
        new BN(0),                            // Day 38: failureModeBitmask (flags=0 ⇒ 0)
        0,                                    // Day 38: remediationCodes
        [...Buffer.alloc(32, 0)],             // Day 38: diagnosisPayloadHash
        0,                                    // Day 38: taxonomyVersion
      )
      .accounts({
        agentRegistration: /* derived elsewhere */ undefined as any,
        oracleConfig: undefined as any,
        epochState: epochStatePda(),
        oracle: oracle.publicKey,
        certificate: certPda(epoch),
        baselineStats: baselinePda(),
        issuerConfig: issuerConfigPda(),
        certificateIssuerProgram: certProgram.programId,
        instructionsSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
        slotHashesSysvar: SYSVAR_SLOT_HASHES_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // The certificate now exists ON THE CERT PROGRAM — written by the CPI.
    const cert: any = await certProgram.account.healthCertificate.fetch(
      certPda(epoch)
    );
    assert.equal(cert.epoch.toNumber(), 1);
    assert.equal(cert.score, 916);
    assert.ok(cert.agentWallet.equals(agent));
  });

  // ── 2. epoch history — advance, submit again, both persist ─────────────────
  it("keeps epoch history queryable on-chain", async () => {
    // AW-02: advance_epoch now needs the OracleConfig + instructions
    // sysvar accounts AND M-of-N cluster Ed25519 attestations carried in
    // the same tx. The integration test scaffold uses a 1-node cluster
    // (provider.wallet is the sole oracle key, so threshold=1). The
    // Tier-2 liveness-fallback path is what makes this single
    // `.rpc()` shape still work in the test validator — the local
    // validator's clock advances past the 2× duration during normal test
    // setup, opening the fallback window. For a production-shape M-of-N
    // test, see tests/aw02_threshold_advance.integration.ts.
    //
    // For the historical-coverage end of this test we exercise the
    // fallback path with the wallet acting as a cluster member.
    const oracleConfig = PublicKey.findProgramAddressSync(
      [enc("oracle_config")],
      oracleProgram.programId,
    )[0];

    await oracleProgram.methods
      .advanceEpoch()
      .accounts({
        epochState: epochStatePda(),
        oracleConfig,
        advancer: oracle.publicKey,
        instructionsSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .rpc();

    const epochState: any = await oracleProgram.account.epochState.fetch(
      epochStatePda()
    );
    assert.equal(epochState.currentEpoch.toNumber(), 2);

    // Submit an epoch-2 score — a NEW certificate PDA.
    const slotAnchor2 = await captureSlotAnchor();
    await oracleProgram.methods
      .submitScore(
        new BN(2), 720, 0, 0, false,
        [...inputCommitment],            // AW-01
        new BN(slotAnchor2.slot.toString()),  // AW-01-EXT slot
        [...slotAnchor2.hash],                // AW-01-EXT block hash
        [...Buffer.alloc(32, 0xab)],          // AW-04: scoringCodeHash (non-zero)
        Buffer.from(JSON.stringify({ v: 1 })),// AW-04: scoreComponentsPayload
        new BN(0),                            // Day 38: failureModeBitmask (flags=0 ⇒ 0)
        0,                                    // Day 38: remediationCodes
        [...Buffer.alloc(32, 0)],             // Day 38: diagnosisPayloadHash
        0,                                    // Day 38: taxonomyVersion
      )
      .accounts({
        agentRegistration: undefined as any,
        oracleConfig: undefined as any,
        epochState: epochStatePda(),
        oracle: oracle.publicKey,
        certificate: certPda(2),
        baselineStats: baselinePda(),
        issuerConfig: issuerConfigPda(),
        certificateIssuerProgram: certProgram.programId,
        instructionsSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
        slotHashesSysvar: SYSVAR_SLOT_HASHES_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // BOTH epoch-1 and epoch-2 certificates exist independently — history.
    const c1: any = await certProgram.account.healthCertificate.fetch(
      certPda(1)
    );
    const c2: any = await certProgram.account.healthCertificate.fetch(
      certPda(2)
    );
    assert.equal(c1.score, 916);
    assert.equal(c2.score, 720);
  });

  // ── 3. get_health reads the latest (current-epoch) certificate ─────────────
  it("get_health reads the current-epoch certificate", async () => {
    // The current epoch is 2; get_health resolves ["cert", agent, 2].
    await oracleProgram.methods
      .getHealth(agent)
      .accounts({
        epochState: epochStatePda(),
        certificate: certPda(2),
      })
      .rpc();
    // Success means the current-epoch certificate resolved and was read.
  });
});
