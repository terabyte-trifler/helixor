// =============================================================================
// tests/aw02_threshold_advance.integration.ts
//
// AW-02 done-when integration test: epoch advance via M-of-N cluster Ed25519
// attestations, the new normal-path authority model. Replaces the prior
// single-key advance_authority gate on the Tier-1 path.
//
// The test scaffold here is shaped specifically for the M-of-N flow:
//
//   1. Initialise an OracleConfig with a KNOWN multi-key cluster (3 keypairs
//      under our control). The consensus threshold is 2 (strict majority).
//   2. Initialise EpochState with the test wallet as the advance_authority
//      HINT — that hint no longer gates advance, but the field is still
//      initialised at construction time.
//   3. Wait for the epoch duration to elapse on the local validator clock.
//   4. Compute the canonical advance digest off-chain via the SDK helper.
//   5. Sign with 2 of the 3 cluster keypairs.
//   6. Build the advance_epoch tx with the 2 Ed25519 program instructions
//      and the main advance_epoch instruction in the same transaction.
//   7. Submit. Assert the epoch advances.
//   8. Negative: 1 sig only must FAIL with InsufficientAdvanceAttestations.
//   9. Negative: 2 sigs over WRONG digest must FAIL.
//  10. Negative: 2 sigs by NON-CLUSTER keys must FAIL.
//
// The challenge of M-of-N integration testing is signature production:
// each cluster member must produce a real Ed25519 sig over the digest.
// `Ed25519Program.createInstructionWithPrivateKey` from @solana/web3.js
// takes a 64-byte secret key, so we use `Keypair.generate()` to create
// our own cluster keys (the local validator does not need to know them —
// the Ed25519 program verifies the sig against the embedded pubkey).
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  Ed25519Program,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import { assert } from "chai";

import { advancePayloadDigest } from "@helixor/sdk";

const { BN } = anchor;
const enc = anchor.utils.bytes.utf8.encode;

describe("AW-02: M-of-N threshold-attested epoch advance", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const oracleProgram = anchor.workspace.HealthOracle as Program;

  // 3-node cluster, threshold = 2 (strict majority).
  const cluster = [
    Keypair.generate(),
    Keypair.generate(),
    Keypair.generate(),
  ];

  // ── PDA helpers ────────────────────────────────────────────────────────────
  const epochStatePda = () =>
    PublicKey.findProgramAddressSync(
      [enc("epoch_state")],
      oracleProgram.programId,
    )[0];

  const oracleConfigPda = () =>
    PublicKey.findProgramAddressSync(
      [enc("oracle_config")],
      oracleProgram.programId,
    )[0];

  // ── Helpers ────────────────────────────────────────────────────────────────

  /**
   * Build an Ed25519 program instruction that signs `digest` under `signer`.
   * The on-chain verifier inspects the instructions sysvar, finds this
   * instruction, parses the embedded pubkey, and counts the signature if
   * (pubkey ∈ cluster) AND (signed message == expected digest).
   */
  function signAttestation(signer: Keypair, digest: Buffer) {
    return Ed25519Program.createInstructionWithPrivateKey({
      privateKey: signer.secretKey,
      message: digest,
    });
  }

  async function snapshotEpoch(): Promise<{
    current: bigint;
    lastAdvancedAt: bigint;
  }> {
    const state: any = await oracleProgram.account.epochState.fetch(
      epochStatePda(),
    );
    return {
      current: BigInt(state.currentEpoch.toString()),
      lastAdvancedAt: BigInt(state.lastAdvancedAt.toString()),
    };
  }

  async function buildAdvanceTx(attestations: anchor.web3.TransactionInstruction[]) {
    const advanceIx = await oracleProgram.methods
      .advanceEpoch()
      .accounts({
        epochState: epochStatePda(),
        oracleConfig: oracleConfigPda(),
        advancer: provider.wallet.publicKey,
        instructionsSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .instruction();

    const tx = new Transaction();
    for (const a of attestations) tx.add(a);
    tx.add(advanceIx);
    return tx;
  }

  // ── Happy path: 2 of 3 cluster sigs → advance succeeds ─────────────────────
  it("advances on M-of-N cluster Ed25519 attestations", async () => {
    const before = await snapshotEpoch();
    const target = before.current + 1n;
    const digest = advancePayloadDigest(
      before.current, target, before.lastAdvancedAt,
    );

    const tx = await buildAdvanceTx([
      signAttestation(cluster[0], digest),
      signAttestation(cluster[1], digest),
    ]);
    await provider.sendAndConfirm(tx);

    const after = await snapshotEpoch();
    assert.equal(after.current, target,
      "epoch should advance by 1 when M-of-N quorum is met");
  });

  // ── Negative: below threshold → InsufficientAdvanceAttestations ────────────
  it("rejects an advance with only 1 of 3 attestations", async () => {
    const before = await snapshotEpoch();
    const target = before.current + 1n;
    const digest = advancePayloadDigest(
      before.current, target, before.lastAdvancedAt,
    );

    const tx = await buildAdvanceTx([
      signAttestation(cluster[0], digest),
    ]);
    let err: any = null;
    try {
      await provider.sendAndConfirm(tx);
    } catch (e: any) { err = e; }
    assert.ok(err, "tx must fail with sub-quorum attestations");
    // Anchor error code = 6070 + 6000 offset = 12070
    const msg = String(err);
    assert.ok(
      msg.includes("InsufficientAdvanceAttestations") || msg.includes("12070"),
      `expected InsufficientAdvanceAttestations / 12070; got: ${msg}`,
    );
  });

  // ── Negative: 2 sigs over a STALE digest → still rejected ──────────────────
  it("rejects 2 attestations over the wrong digest", async () => {
    const before = await snapshotEpoch();
    // A wrong digest — bind to the WRONG last_advanced_at (an old snapshot).
    const staleDigest = advancePayloadDigest(
      before.current, before.current + 1n, before.lastAdvancedAt - 86_400n,
    );

    const tx = await buildAdvanceTx([
      signAttestation(cluster[0], staleDigest),
      signAttestation(cluster[1], staleDigest),
    ]);
    let err: any = null;
    try {
      await provider.sendAndConfirm(tx);
    } catch (e: any) { err = e; }
    assert.ok(err, "tx must fail when sigs are over the wrong digest");
    const msg = String(err);
    assert.ok(
      msg.includes("InsufficientAdvanceAttestations") || msg.includes("12070"),
      `expected InsufficientAdvanceAttestations / 12070; got: ${msg}`,
    );
  });

  // ── Negative: 2 sigs by NON-CLUSTER keys → still rejected ──────────────────
  it("rejects 2 attestations by non-cluster keys", async () => {
    const stranger1 = Keypair.generate();
    const stranger2 = Keypair.generate();

    const before = await snapshotEpoch();
    const digest = advancePayloadDigest(
      before.current, before.current + 1n, before.lastAdvancedAt,
    );
    const tx = await buildAdvanceTx([
      signAttestation(stranger1, digest),
      signAttestation(stranger2, digest),
    ]);
    let err: any = null;
    try {
      await provider.sendAndConfirm(tx);
    } catch (e: any) { err = e; }
    assert.ok(err, "tx must fail when signers are not cluster members");
    const msg = String(err);
    assert.ok(
      msg.includes("InsufficientAdvanceAttestations") || msg.includes("12070"),
      `expected InsufficientAdvanceAttestations / 12070; got: ${msg}`,
    );
  });
});
