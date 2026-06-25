// =============================================================================
// phylanx-sdk/src/baseline_provenance.ts — AW-03 client-side verification.
//
// THE AW-03 PROBLEM
// -----------------
// A HealthCertificate carries a 32-byte `baseline_hash` — a SHA-256 commitment
// over the statistical baseline the cluster scored against. The hash alone
// proves nothing about PROVENANCE: a third party (a DeFi protocol reading the
// cert) cannot see the bytes behind the hash, so it cannot audit whether the
// baseline was legitimately derived from observable behaviour. A compromised
// oracle DB could substitute any 32-byte value at commit time and the
// certificate would happily reference it.
//
// THE FIX (on chain)
// ------------------
// Day 3's `commit_baseline` now also `init`s a `BaselineDataAccount` PDA that
// stores the canonical-JSON baseline payload bytes verbatim. The on-chain
// handler enforces, at write time:
//
//     sha256(baseline_data.payload) == agent_registration.baseline_hash
//
// The account is write-once (Anchor `init` against a `commit_nonce`-keyed
// PDA), so the invariant is permanent and a rotation produces a NEW account
// instead of overwriting the old one. The HealthCertificate carries the
// `baseline_commit_nonce` (v6 field) so a consumer reading the cert can
// derive the exact `BaselineDataAccount` PDA — even after the agent's
// registration has rotated to a newer baseline.
//
// THE FIX (this module)
// ---------------------
// Given a decoded HealthCertificate, fetch the corresponding
// `BaselineDataAccount` from RPC, recompute `sha256(payload)`, and assert
// it equals `cert.baselineHash`. If it does, the consumer has cryptographic
// proof that the baseline behind this cert was published on chain — not
// just attested by the cluster — and that the bytes have not been swapped
// since.
//
// PROVENANCE COMPOSITION
// ----------------------
// AW-01 verifies INPUT provenance (transactions + windows the cluster
// scored). AW-03 verifies BASELINE provenance (the statistical reference
// the inputs were scored against). Together they close the trust gap: a
// consumer who passes BOTH checks knows the cluster computed `score` over
// inputs it can see, against a baseline it can audit.
//
// =============================================================================

import { createHash } from "crypto";
import { Connection, PublicKey } from "@solana/web3.js";

import {
  decodeBaselineDataAccount,
  type DecodedBaselineDataAccount,
  type DecodedHealthCertificate,
} from "./decode";
import { baselineDataPda } from "./pdas";

// =============================================================================
// Public types
// =============================================================================

/**
 * Why a baseline-provenance check refused a certificate. Mirrors the
 * AW-01 `ProvenanceRejection` enum so consumers can switch over a single
 * union of reasons across both checks.
 */
export enum BaselineProvenanceRejection {
  /** The cert is pre-AW-03 (`baselineCommitNonce === 0n`) — no DA account
   *  exists to verify against. Caller decides whether to treat this as
   *  fatal (strict mode) or fall back to a hash-only commitment check. */
  NoDataAccount = "no_data_account",
  /** The DA account PDA derived from the cert has no on-chain account.
   *  This is anomalous — it implies the cert was issued before the DA
   *  account was written, or the account was never created (broken
   *  cluster). */
  AccountNotFound = "account_not_found",
  /** The DA account exists but its bytes do not deserialise as a
   *  `BaselineDataAccount` (truncated, wrong discriminator, …). */
  AccountUnreadable = "account_unreadable",
  /** `sha256(account.payload) !== cert.baselineHash`. The cluster's
   *  on-chain hash binding is broken — refuse. */
  HashMismatch = "hash_mismatch",
  /** The DA account belongs to a different agent than the cert.
   *  Should be unreachable for a well-formed PDA derivation, but worth
   *  defending against. */
  AgentMismatch = "agent_mismatch",
  /** The DA account's commit_nonce does not match the cert's
   *  `baselineCommitNonce`. Unreachable for a well-formed PDA, defended
   *  for the same reason. */
  NonceMismatch = "nonce_mismatch",
}

export interface BaselineProvenanceOk {
  readonly ok: true;
  /** The verified DA account (so the caller can inspect the payload). */
  readonly dataAccount: DecodedBaselineDataAccount;
  /** The PDA address that was fetched. */
  readonly dataAccountAddress: PublicKey;
}

export interface BaselineProvenanceFail {
  readonly ok: false;
  readonly reason: BaselineProvenanceRejection;
  readonly detail: string;
}

export type BaselineProvenanceResult =
  | BaselineProvenanceOk
  | BaselineProvenanceFail;

// =============================================================================
// Pure helpers
// =============================================================================

/**
 * Compute SHA-256 of the canonical payload bytes. The returned 32 bytes
 * MUST equal both `cert.baselineHash` AND `account.baselineHash` for a
 * well-formed AW-03 commit.
 */
export function sha256Payload(payload: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(payload).digest());
}

/**
 * Parse the canonical-JSON payload bytes into the statistical baseline.
 * The shape mirrors `baseline.hashing.build_hash_payload` on the Python
 * side. Floats are STRINGS (pre-canonicalised by the off-chain hasher) —
 * the consumer parses them back to numbers if it needs to inspect them.
 *
 * This function is a pure helper for callers that want to AUDIT the
 * baseline content; `verifyBaselineProvenance` does not call it (it
 * verifies the bytes via hash, which does not require parsing).
 */
export interface ParsedBaselinePayload {
  v: number;
  schema_fp: string;
  means: string[];
  stds: string[];
  txtype_dist: string[];
  action_entropy: string;
  success_rate_30d: string;
  daily_success_rate_series: string[];
}

export function decodeBaselinePayload(
  payload: Uint8Array
): ParsedBaselinePayload {
  const text = Buffer.from(payload).toString("utf-8");
  return JSON.parse(text) as ParsedBaselinePayload;
}

// =============================================================================
// Byte equality
// =============================================================================

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function fail(
  reason: BaselineProvenanceRejection,
  detail: string
): BaselineProvenanceFail {
  return { ok: false, reason, detail };
}

// =============================================================================
// The verifier
// =============================================================================

/**
 * Verify the cert's baseline provenance against the on-chain DA account.
 *
 * Returns OK iff:
 *   - the cert is v6+ (carries a non-zero baseline_commit_nonce),
 *   - the BaselineDataAccount PDA exists on chain,
 *   - it decodes cleanly,
 *   - its agent_wallet + commit_nonce match the cert,
 *   - `sha256(account.payload) === cert.baselineHash`.
 *
 * Refuses (with a specific rejection reason) otherwise. This is the
 * AW-03 contract: a consumer who calls this BEFORE acting on a cert's
 * score has cryptographic proof of baseline provenance.
 *
 * USAGE
 *   const cert = decodeHealthCertificate(certInfo.data);
 *   const result = await verifyBaselineProvenance(connection, healthOracleProgram, cert);
 *   if (!result.ok) refuse(result.reason);
 *
 * NOTE on pre-AW-03 certs: a `baselineCommitNonce === 0n` cert is
 * pre-v6 — no DA account was written. The verifier returns
 * `NoDataAccount`. Callers in STRICT mode should treat that as a
 * refusal. Callers in MIGRATION mode (still serving legacy agents) can
 * decide to fall back to the hash-only commitment.
 */
export async function verifyBaselineProvenance(
  connection: Connection,
  healthOracleProgram: PublicKey,
  cert: Pick<
    DecodedHealthCertificate,
    "agentWallet" | "baselineHash" | "baselineCommitNonce"
  >
): Promise<BaselineProvenanceResult> {
  // Pre-AW-03 certs have a zero nonce — no DA account exists to verify.
  if (cert.baselineCommitNonce === 0n) {
    return fail(
      BaselineProvenanceRejection.NoDataAccount,
      "cert is pre-AW-03 (baselineCommitNonce == 0); no BaselineDataAccount " +
        "was written; consumer must decide whether to fall back to the " +
        "hash-only commitment or refuse"
    );
  }

  const agent = new PublicKey(cert.agentWallet);
  const dataAccountAddress = baselineDataPda(
    healthOracleProgram,
    agent,
    cert.baselineCommitNonce
  );

  const info = await connection.getAccountInfo(dataAccountAddress);
  if (info === null) {
    return fail(
      BaselineProvenanceRejection.AccountNotFound,
      `BaselineDataAccount ${dataAccountAddress.toBase58()} not found on chain ` +
        `for agent=${agent.toBase58()} commit_nonce=${cert.baselineCommitNonce}`
    );
  }

  let decoded: DecodedBaselineDataAccount;
  try {
    decoded = decodeBaselineDataAccount(info.data);
  } catch (err) {
    return fail(
      BaselineProvenanceRejection.AccountUnreadable,
      `failed to decode BaselineDataAccount at ${dataAccountAddress.toBase58()}: ${
        (err as Error).message
      }`
    );
  }

  // Defensive cross-checks — should be unreachable given the PDA seed,
  // but they cost a few comparisons and surface bugs loudly.
  if (!bytesEq(decoded.agentWallet, cert.agentWallet)) {
    return fail(
      BaselineProvenanceRejection.AgentMismatch,
      `DA account agent_wallet (${Buffer.from(decoded.agentWallet)
        .toString("hex")
        .slice(0, 16)}…) does not match cert agent_wallet`
    );
  }
  if (decoded.commitNonce !== cert.baselineCommitNonce) {
    return fail(
      BaselineProvenanceRejection.NonceMismatch,
      `DA account commit_nonce ${decoded.commitNonce} does not match cert ` +
        `baselineCommitNonce ${cert.baselineCommitNonce}`
    );
  }

  // THE HASH BINDING — the AW-03 invariant.
  const recomputed = sha256Payload(decoded.payload);
  if (!bytesEq(recomputed, cert.baselineHash)) {
    return fail(
      BaselineProvenanceRejection.HashMismatch,
      `sha256(payload) = ${Buffer.from(recomputed)
        .toString("hex")
        .slice(0, 16)}… does not match cert.baselineHash = ${Buffer.from(
        cert.baselineHash
      )
        .toString("hex")
        .slice(0, 16)}…`
    );
  }

  return {
    ok: true,
    dataAccount: decoded,
    dataAccountAddress,
  };
}
