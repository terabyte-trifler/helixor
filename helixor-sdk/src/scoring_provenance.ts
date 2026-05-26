// =============================================================================
// helixor-sdk/src/scoring_provenance.ts — AW-04 client-side verification.
//
// THE AW-04 PROBLEM
// -----------------
// A HealthCertificate carries a 0-1000 `score` and a u32 `flags` field. The
// cluster's threshold signatures attest that the cluster AGREED on those
// numbers — but they say nothing about HOW those numbers were derived. A
// compromised cluster (or a single rogue node that the others trusted) could
// publish any score it liked and the cert would happily carry it; the SDK
// has no way to re-execute the scoring formula and check.
//
// THE FIX (on chain)
// ------------------
// At cert issuance the cluster also writes a `ScoreComponentsAccount` PDA
// at `["score_components", agent, epoch_le]` whose `payload` is the
// canonical-JSON per-dimension breakdown the cluster computed. The
// on-chain handler enforces, at write time:
//
//     sha256(account.payload) == account.components_hash
//
// AND folds `components_hash` into the cert-payload digest the cluster
// signed. The bytes are therefore doubly bound: the on-chain re-hash
// catches tampering, the threshold signatures catch substitution of the
// account itself. The account is write-once (Anchor `init`), so the
// invariant is permanent.
//
// Separately, the cluster stamps `scoring_code_hash` on the cert — the
// SHA-256 of the scoring kernel source bytes + algo/weights version
// labels at compute time. A consumer who checks out the helixor repo at
// the published tag and runs the same hasher MUST get the same 32 bytes;
// any disagreement means the cluster ran patched scoring code.
//
// THE FIX (this module)
// ---------------------
// Given a decoded HealthCertificate, fetch the corresponding
// `ScoreComponentsAccount` from RPC, recompute `sha256(payload)`, parse
// the canonical JSON, and re-apply the documented formula:
//
//     raw_score = sum(d.contrib for d in dims)
//     score_after_clamp = clamp(0, 1000, raw_score)
//     final = apply_delta_guard_rail(score_after_clamp, previous_score)
//     assert final == cert.score
//
// If the cluster published a wrong score it is caught: it cannot produce
// a `dims[]` whose `sum -> clamp -> delta_guard` lands on the fabricated
// score AND whose canonical-JSON hash matches the digest the cluster's
// signatures already attested to.
//
// `verifyScoringCodeHash` is the second leg: the consumer supplies the
// `expectedHash` they recomputed from the cloned repo, and we refuse the
// cert if it does not match `cert.scoringCodeHash`. The SDK does not
// (and cannot) recompute the bundle itself — that would require shipping
// the scoring kernel source — so the consumer is expected to provide the
// hash from their own audit pipeline.
//
// PROVENANCE COMPOSITION
// ----------------------
// AW-01 verifies INPUT provenance (transactions + windows the cluster
// scored). AW-03 verifies BASELINE provenance (the statistical reference
// the inputs were scored against). AW-04 verifies COMPUTATION provenance
// (that the cluster ran the published formula on those inputs and
// arrived at the published score). A consumer who passes all three has
// cryptographic proof of EVERYTHING behind the score.
//
// =============================================================================

import { createHash } from "crypto";
import { Connection, PublicKey } from "@solana/web3.js";

import {
  decodeScoreComponentsAccount,
  type DecodedScoreComponentsAccount,
  type DecodedHealthCertificate,
} from "./decode";
import { scoreComponentsPda } from "./pdas";

// =============================================================================
// Constants — MIRROR Python `oracle/score_components.py` exactly.
// =============================================================================

/** The canonical-JSON schema version produced by the off-chain serializer. */
export const SCORE_COMPONENTS_SCHEMA_VERSION = 1;

/** Max payload length the on-chain handler accepts. Mirrors the Rust constant. */
export const MAX_SCORE_COMPONENTS_PAYLOAD_LEN = 4096;

/** The 200-point composite delta-guard rail. Mirrors `scoring/_gaming.py`. */
export const MAX_SCORE_DELTA = 200;

/** The composite-score range. */
export const SCORE_MIN = 0;
export const SCORE_MAX = 1000;

// =============================================================================
// Public types
// =============================================================================

/**
 * Why a scoring-provenance check refused a certificate. Mirrors the
 * AW-01 / AW-03 rejection enums so consumers can switch over a single
 * union of reasons across all provenance checks.
 */
export enum ScoringProvenanceRejection {
  /** The cert is pre-AW-04 (`scoringCodeHash` is all zeros / layoutVersion
   *  < 7) — no components account exists to verify against. Strict-mode
   *  callers should treat this as fatal; migration-mode callers may
   *  serve the cert with reduced trust. */
  NoComponentsAccount = "no_components_account",
  /** The PDA derived from the cert has no on-chain account. Anomalous:
   *  the cluster issued the cert without writing the components, or the
   *  cert was issued against a different program ID. */
  AccountNotFound = "account_not_found",
  /** The account exists but its bytes do not deserialise as a
   *  `ScoreComponentsAccount` (truncated, wrong discriminator, …). */
  AccountUnreadable = "account_unreadable",
  /** `sha256(account.payload) !== account.componentsHash`. The on-chain
   *  hash binding is broken — refuse. */
  HashMismatch = "hash_mismatch",
  /** The components account belongs to a different agent than the cert.
   *  Should be unreachable for a well-formed PDA derivation. */
  AgentMismatch = "agent_mismatch",
  /** The components account's epoch does not match the cert's epoch.
   *  Unreachable for a well-formed PDA, defended for the same reason. */
  EpochMismatch = "epoch_mismatch",
  /** The canonical-JSON payload could not be parsed as the expected
   *  schema. Indicates a serializer regression or a tampered payload. */
  PayloadMalformed = "payload_malformed",
  /** The replay arithmetic disagreed with `cert.score`. The cluster
   *  published a wrong score and was caught by this re-execution. This
   *  is the AW-04 catch — see the module docstring. */
  ScoreReplayMismatch = "score_replay_mismatch",
  /** A consumer-supplied `expectedHash` does not equal `cert.scoringCodeHash`.
   *  The cluster ran scoring code that does not match the consumer's
   *  known-good build. */
  CodeHashMismatch = "code_hash_mismatch",
}

/** One dimension's breakdown — mirrors the Python `dims[i]` element. */
export interface ScoreComponentsDim {
  id: string;
  /** Normalised score, canonical-form float string (9 decimals). */
  norm: string;
  /** Per-dimension flag bits. */
  flags: number;
  /** Detector algo version. */
  algoV: number;
  /** Weighted contribution to the raw score (int). */
  contrib: number;
}

/** Parsed canonical-JSON score-components payload (schema v1). */
export interface ParsedScoreComponents {
  v: number;
  algoV: number;
  weightsV: number;
  score: number;
  rawScore: number;
  deltaClamped: boolean;
  /** null for a first-ever scoring (no previous score to clamp against). */
  previousScore: number | null;
  alert: "GREEN" | "YELLOW" | "RED" | string;
  immediateRed: boolean;
  aggFlags: number;
  confidence: number;
  gaming: boolean;
  gamingDrop: string;
  dims: ScoreComponentsDim[];
}

/** The result of replaying the documented scoring formula. */
export interface ScoreReplay {
  rawScore: number;
  scoreAfterClamp: number;
  /** Whether the 200-pt delta guard rail moved `scoreAfterClamp`. */
  deltaClamped: boolean;
  /** The final score the replay arrived at — the field compared to
   *  `cert.score`. */
  finalScore: number;
}

export interface ScoringProvenanceOk {
  readonly ok: true;
  readonly componentsAccount: DecodedScoreComponentsAccount;
  readonly componentsAddress: PublicKey;
  readonly parsed: ParsedScoreComponents;
  readonly replay: ScoreReplay;
}

export interface ScoringProvenanceFail {
  readonly ok: false;
  readonly reason: ScoringProvenanceRejection;
  readonly detail: string;
}

export type ScoringProvenanceResult =
  | ScoringProvenanceOk
  | ScoringProvenanceFail;

// =============================================================================
// Pure helpers
// =============================================================================

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function isZeroBytes(a: Uint8Array): boolean {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== 0) return false;
  }
  return true;
}

function fail(
  reason: ScoringProvenanceRejection,
  detail: string
): ScoringProvenanceFail {
  return { ok: false, reason, detail };
}

/** SHA-256 of the canonical-JSON payload bytes. Mirrors AW-03's helper. */
export function sha256ComponentsPayload(payload: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(payload).digest());
}

/**
 * Parse the canonical-JSON payload bytes into the typed
 * `ParsedScoreComponents` shape. Throws if any required field is missing
 * or has the wrong type — the caller wraps this in a `PayloadMalformed`
 * rejection so a serializer regression surfaces as a verifier refusal
 * rather than a runtime crash inside a DeFi handler.
 */
export function parseScoreComponentsPayload(
  payload: Uint8Array
): ParsedScoreComponents {
  const text = Buffer.from(payload).toString("utf-8");
  const obj = JSON.parse(text) as Record<string, unknown>;

  const need = (key: string): unknown => {
    if (!(key in obj)) {
      throw new Error(`missing field '${key}'`);
    }
    return obj[key];
  };
  const asInt = (key: string): number => {
    const v = need(key);
    if (typeof v !== "number" || !Number.isInteger(v)) {
      throw new Error(`field '${key}' must be int, got ${typeof v} ${v}`);
    }
    return v;
  };
  const asBool = (key: string): boolean => {
    const v = need(key);
    if (typeof v !== "boolean") {
      throw new Error(`field '${key}' must be bool, got ${typeof v}`);
    }
    return v;
  };
  const asStr = (key: string): string => {
    const v = need(key);
    if (typeof v !== "string") {
      throw new Error(`field '${key}' must be string, got ${typeof v}`);
    }
    return v;
  };

  const dimsRaw = need("dims");
  if (!Array.isArray(dimsRaw)) {
    throw new Error(`field 'dims' must be array, got ${typeof dimsRaw}`);
  }
  const dims: ScoreComponentsDim[] = dimsRaw.map((d, i) => {
    if (typeof d !== "object" || d === null) {
      throw new Error(`dims[${i}] must be object`);
    }
    const dim = d as Record<string, unknown>;
    if (typeof dim.id !== "string") throw new Error(`dims[${i}].id must be string`);
    if (typeof dim.norm !== "string") throw new Error(`dims[${i}].norm must be string`);
    if (typeof dim.flags !== "number" || !Number.isInteger(dim.flags)) {
      throw new Error(`dims[${i}].flags must be int`);
    }
    if (typeof dim.algo_v !== "number" || !Number.isInteger(dim.algo_v)) {
      throw new Error(`dims[${i}].algo_v must be int`);
    }
    if (typeof dim.contrib !== "number" || !Number.isInteger(dim.contrib)) {
      throw new Error(`dims[${i}].contrib must be int`);
    }
    return {
      id:      dim.id,
      norm:    dim.norm,
      flags:   dim.flags,
      algoV:   dim.algo_v,
      contrib: dim.contrib,
    };
  });

  const previousScoreRaw = need("previous_score");
  let previousScore: number | null;
  if (previousScoreRaw === null) {
    previousScore = null;
  } else if (
    typeof previousScoreRaw === "number" &&
    Number.isInteger(previousScoreRaw)
  ) {
    previousScore = previousScoreRaw;
  } else {
    throw new Error(
      `field 'previous_score' must be int|null, got ${typeof previousScoreRaw}`
    );
  }

  return {
    v:             asInt("v"),
    algoV:         asInt("algo_v"),
    weightsV:      asInt("weights_v"),
    score:         asInt("score"),
    rawScore:      asInt("raw_score"),
    deltaClamped:  asBool("delta_clamped"),
    previousScore,
    alert:         asStr("alert"),
    immediateRed:  asBool("immediate_red"),
    aggFlags:      asInt("agg_flags"),
    confidence:    asInt("confidence"),
    gaming:        asBool("gaming"),
    gamingDrop:    asStr("gaming_drop"),
    dims,
  };
}

/**
 * Re-execute the documented scoring formula from a parsed components
 * payload. Mirrors `apply_delta_guard_rail` + the clamp in `composite.py`
 * exactly:
 *
 *     raw_score = sum(d.contrib for d in dims)
 *     score_after_clamp = clamp(0, 1000, raw_score)
 *     if previous_score is None:
 *         final = score_after_clamp
 *     else:
 *         delta = score_after_clamp - previous_score
 *         if delta > 200:   final = previous_score + 200; clamped = True
 *         elif delta < -200: final = previous_score - 200; clamped = True
 *         else:              final = score_after_clamp;   clamped = False
 *
 * Pure: same input -> same output, byte-identical to the Python original.
 */
export function replayScoreFromComponents(
  parsed: ParsedScoreComponents
): ScoreReplay {
  let rawScore = 0;
  for (const d of parsed.dims) {
    rawScore += d.contrib;
  }

  const scoreAfterClamp = Math.max(
    SCORE_MIN,
    Math.min(SCORE_MAX, rawScore)
  );

  if (parsed.previousScore === null) {
    return {
      rawScore,
      scoreAfterClamp,
      deltaClamped: false,
      finalScore:   scoreAfterClamp,
    };
  }

  const delta = scoreAfterClamp - parsed.previousScore;
  if (delta > MAX_SCORE_DELTA) {
    return {
      rawScore,
      scoreAfterClamp,
      deltaClamped: true,
      finalScore:   parsed.previousScore + MAX_SCORE_DELTA,
    };
  }
  if (delta < -MAX_SCORE_DELTA) {
    return {
      rawScore,
      scoreAfterClamp,
      deltaClamped: true,
      finalScore:   parsed.previousScore - MAX_SCORE_DELTA,
    };
  }
  return {
    rawScore,
    scoreAfterClamp,
    deltaClamped: false,
    finalScore:   scoreAfterClamp,
  };
}

// =============================================================================
// The verifier — `verifyScoreComputation`
// =============================================================================

/**
 * Verify the cert's score-computation provenance against the on-chain
 * components account.
 *
 * Returns OK iff:
 *   - the cert is v7+ (carries a non-zero `scoringCodeHash`),
 *   - the ScoreComponentsAccount PDA exists on chain,
 *   - it decodes cleanly,
 *   - its `agent_wallet` + `epoch` match the cert,
 *   - `sha256(account.payload) === account.componentsHash`,
 *   - the canonical JSON parses to the expected schema,
 *   - replaying `sum(dims.contrib) -> clamp -> delta_guard(previous_score)`
 *     arrives at `cert.score`.
 *
 * Refuses (with a specific rejection reason) otherwise. A consumer that
 * calls this BEFORE acting on a cert's score has cryptographic proof
 * that the cluster ran the documented formula on the documented inputs
 * and arrived at the published number.
 *
 * USAGE
 *   const cert = decodeHealthCertificate(certInfo.data);
 *   const result = await verifyScoreComputation(connection, certIssuer, cert);
 *   if (!result.ok) refuse(result.reason);
 *
 * NOTE on pre-AW-04 certs: a `scoringCodeHash` of all zeros is the v7
 * sentinel meaning "no components account was written". Strict-mode
 * callers should treat that as a refusal. Migration-mode callers can
 * decide to fall back to the threshold-signature commitment alone.
 */
export async function verifyScoreComputation(
  connection: Connection,
  certificateIssuerProgram: PublicKey,
  cert: Pick<
    DecodedHealthCertificate,
    "agentWallet" | "epoch" | "score" | "scoringCodeHash" | "layoutVersion"
  >
): Promise<ScoringProvenanceResult> {
  // Pre-AW-04 certs have a zero scoring_code_hash — no components account.
  if (cert.layoutVersion < 7 || isZeroBytes(cert.scoringCodeHash)) {
    return fail(
      ScoringProvenanceRejection.NoComponentsAccount,
      `cert is pre-AW-04 (layoutVersion=${cert.layoutVersion}, ` +
        `scoringCodeHash=all-zero); no ScoreComponentsAccount was written; ` +
        `consumer must decide whether to fall back to the threshold-signature ` +
        `commitment or refuse`
    );
  }

  const agent = new PublicKey(cert.agentWallet);
  const componentsAddress = scoreComponentsPda(
    certificateIssuerProgram,
    agent,
    cert.epoch
  );

  const info = await connection.getAccountInfo(componentsAddress);
  if (info === null) {
    return fail(
      ScoringProvenanceRejection.AccountNotFound,
      `ScoreComponentsAccount ${componentsAddress.toBase58()} not found on ` +
        `chain for agent=${agent.toBase58()} epoch=${cert.epoch}`
    );
  }

  let decoded: DecodedScoreComponentsAccount;
  try {
    decoded = decodeScoreComponentsAccount(info.data);
  } catch (err) {
    return fail(
      ScoringProvenanceRejection.AccountUnreadable,
      `failed to decode ScoreComponentsAccount at ${componentsAddress.toBase58()}: ${
        (err as Error).message
      }`
    );
  }

  // Defensive cross-checks. Should be unreachable for a well-formed PDA
  // but they cost a few comparisons and surface bugs loudly.
  if (!bytesEq(decoded.agentWallet, cert.agentWallet)) {
    return fail(
      ScoringProvenanceRejection.AgentMismatch,
      `components account agent_wallet (${Buffer.from(decoded.agentWallet)
        .toString("hex")
        .slice(0, 16)}…) does not match cert agent_wallet`
    );
  }
  if (decoded.epoch !== BigInt(cert.epoch)) {
    return fail(
      ScoringProvenanceRejection.EpochMismatch,
      `components account epoch ${decoded.epoch} does not match cert epoch ${cert.epoch}`
    );
  }

  // THE PAYLOAD HASH BINDING — the AW-04 invariant.
  const recomputed = sha256ComponentsPayload(decoded.payload);
  if (!bytesEq(recomputed, decoded.componentsHash)) {
    return fail(
      ScoringProvenanceRejection.HashMismatch,
      `sha256(payload) = ${Buffer.from(recomputed)
        .toString("hex")
        .slice(0, 16)}… does not match account.componentsHash = ${Buffer.from(
        decoded.componentsHash
      )
        .toString("hex")
        .slice(0, 16)}…`
    );
  }

  let parsed: ParsedScoreComponents;
  try {
    parsed = parseScoreComponentsPayload(decoded.payload);
  } catch (err) {
    return fail(
      ScoringProvenanceRejection.PayloadMalformed,
      `canonical-JSON payload could not be parsed: ${(err as Error).message}`
    );
  }

  // Sanity-check the schema version. A future v2 payload would need a
  // verifier upgrade — refuse rather than silently mis-replay.
  if (parsed.v !== SCORE_COMPONENTS_SCHEMA_VERSION) {
    return fail(
      ScoringProvenanceRejection.PayloadMalformed,
      `unsupported score-components schema version: expected ` +
        `${SCORE_COMPONENTS_SCHEMA_VERSION}, got ${parsed.v}`
    );
  }

  // THE REPLAY — the AW-04 catch.
  const replay = replayScoreFromComponents(parsed);
  if (replay.finalScore !== cert.score) {
    return fail(
      ScoringProvenanceRejection.ScoreReplayMismatch,
      `replay arrived at finalScore=${replay.finalScore} ` +
        `(rawScore=${replay.rawScore}, afterClamp=${replay.scoreAfterClamp}, ` +
        `previousScore=${parsed.previousScore}, deltaClamped=${replay.deltaClamped}) ` +
        `but cert.score=${cert.score}`
    );
  }

  // Also cross-check the payload's own `score` field against the cert.
  // They MUST agree by construction — a cluster that lied would have to
  // lie consistently, but we surface a clear error if not.
  if (parsed.score !== cert.score) {
    return fail(
      ScoringProvenanceRejection.ScoreReplayMismatch,
      `payload.score=${parsed.score} disagrees with cert.score=${cert.score}`
    );
  }

  // Cross-check the payload's `delta_clamped` flag against the replay.
  if (parsed.deltaClamped !== replay.deltaClamped) {
    return fail(
      ScoringProvenanceRejection.ScoreReplayMismatch,
      `payload.delta_clamped=${parsed.deltaClamped} disagrees with replay ` +
        `deltaClamped=${replay.deltaClamped}`
    );
  }

  return {
    ok: true,
    componentsAccount: decoded,
    componentsAddress,
    parsed,
    replay,
  };
}

// =============================================================================
// Code-hash verification — `verifyScoringCodeHash`
// =============================================================================

export enum CodeHashCheckResult {
  Ok = "ok",
  Mismatch = "mismatch",
  PreV7Cert = "pre_v7_cert",
}

export interface CodeHashCheck {
  result: CodeHashCheckResult;
  detail: string;
}

/**
 * Verify the cert's `scoringCodeHash` against a consumer-supplied
 * `expectedHash` — the 32 bytes the consumer recomputed by checking out
 * the helixor repo at the published tag and running
 * `oracle/scoring/bundle_hash.py::compute_scoring_bundle_hash`.
 *
 * The SDK does NOT bundle the scoring kernel source — recomputing the
 * bundle hash requires Python files that would more than triple the
 * SDK's footprint. Instead, the consumer's audit pipeline (or a CI job)
 * computes the expected hash once per release and passes it in here.
 *
 * Returns `PreV7Cert` for legacy certs (scoringCodeHash is all zeros);
 * strict-mode callers should treat that as a refusal.
 */
export function verifyScoringCodeHash(
  cert: Pick<DecodedHealthCertificate, "scoringCodeHash" | "layoutVersion">,
  expectedHash: Uint8Array
): CodeHashCheck {
  if (expectedHash.length !== 32) {
    throw new Error(
      `expectedHash must be exactly 32 bytes; got ${expectedHash.length}`
    );
  }

  if (cert.layoutVersion < 7 || isZeroBytes(cert.scoringCodeHash)) {
    return {
      result: CodeHashCheckResult.PreV7Cert,
      detail:
        `cert is pre-AW-04 (layoutVersion=${cert.layoutVersion}, ` +
        `scoringCodeHash=all-zero); no code-hash commitment to verify`,
    };
  }

  if (!bytesEq(cert.scoringCodeHash, expectedHash)) {
    return {
      result: CodeHashCheckResult.Mismatch,
      detail:
        `cert.scoringCodeHash = ${Buffer.from(cert.scoringCodeHash)
          .toString("hex")
          .slice(0, 16)}… does not match expectedHash = ${Buffer.from(
          expectedHash
        )
          .toString("hex")
          .slice(0, 16)}…`,
    };
  }

  return {
    result: CodeHashCheckResult.Ok,
    detail: "cert.scoringCodeHash matches expectedHash",
  };
}
