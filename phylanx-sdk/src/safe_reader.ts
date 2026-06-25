// =============================================================================
// phylanx-sdk/src/safe_reader.ts — VULN-23 consumer-side guard rails.
//
// THE VULN-23 ATTACK
// ------------------
// A DeFi protocol that gates a loan on a Phylanx trust score, but reads the
// raw cert with `getScore(agent)`, can be drained two ways:
//
//   1. **STALE CERT** — the protocol reads a cert from days ago when the
//      score was high, even though the live cert (or absence of one) tells
//      a different story today.
//
//   2. **VELOCITY ATTACK** — the attacker pumps an agent's score across a
//      few epochs (sybil reputation grind), then borrows against the peak
//      a few minutes before an adverse downgrade lands on chain.
//
// The off-chain scoring pipeline already CLAMPS per-epoch deltas to ±200
// (phylanx-oracle/scoring/_gaming.py — `apply_delta_guard_rail`), but a
// consumer reading the chain has no way to *verify* that clamp held, nor
// to refuse a cert that is days old. This file is the SDK primitive that
// gives DeFi protocols both guards for free.
//
// THE CONTRACT
// ------------
// `SafeCertReader.getSafeScore(agent)` returns a discriminated union:
//
//   { ok: true,  score, alert, epoch, issuedAt }
//   { ok: false, reason: RejectReason, detail: string }
//
// `reason` is the machine-readable signal a protocol switches on; `detail`
// is the human-readable string for logs / user-facing errors. NEVER fall
// through to a default-allow on `ok: false` — the whole point of this
// wrapper is to make refusal the safe default.
//
// WHY NOT JUST ENFORCE ON CHAIN?
// ------------------------------
// The on-chain HealthCertificate has `issued_at` (so freshness is
// chain-verifiable) but no `previous_score` field (so on-chain velocity
// would require a 178-byte schema change to every cert account already in
// existence — backwards-incompatible storage migration). The audit accepts
// consumer-side checks for velocity because the score window is just a
// batched RPC read away.
// =============================================================================

import { PublicKey } from "@solana/web3.js";

import { AlertTier, EpochScore } from "./types";


// =============================================================================
// Constants — these are the audit-mandated thresholds. Bumping them is
// a security decision, NOT a perf knob — change with a written justification.
// =============================================================================

/**
 * The oldest a cert may be and still be honoured. Older = `STALE_CERT`.
 *
 * 48 hours is the audit-mandated ceiling. Daily-epoch cadence + this
 * window means a healthy agent always has a fresh-enough cert in steady
 * state; a 48h+ gap means scoring is broken or the agent has dropped out.
 */
export const CERT_MAX_AGE_SECONDS = 48 * 60 * 60;

/**
 * The maximum total score swing tolerated across the velocity window.
 *
 * Mirrors `MAX_SCORE_DELTA` in `phylanx-oracle/scoring/_gaming.py`
 * (per-epoch clamp = ±200). The off-chain pipeline guarantees no SINGLE
 * epoch jumps more than ±200; this consumer check enforces the AGGREGATE
 * across the rolling window stays within the same envelope.
 *
 * If you ever see this trip in prod it means EITHER the off-chain clamp
 * has been bypassed (investigate IMMEDIATELY) OR a legitimate multi-epoch
 * drift exceeded the velocity envelope (raise this number with the audit).
 */
export const MAX_SCORE_VELOCITY = 200;

/**
 * How many epochs of history the velocity check spans (inclusive of the
 * current epoch). 3 = "this epoch + the two before it".
 */
export const VELOCITY_WINDOW_EPOCHS = 3;

/**
 * Minimum number of certs the window must contain for the velocity
 * check to be MEANINGFUL. A single cert proves the agent has a score
 * but tells us nothing about whether the score is volatile.
 */
export const MIN_HISTORY_REQUIRED = 2;


// =============================================================================
// SEC-1 — not-investment-advice advisory disclaimer
// =============================================================================
//
// DeFi protocols consume cert scores to size loans. To keep the
// cluster's posture as a *technical trust signal* (and not as an
// implicit recommendation under IA Act §202(a)(11) / SEBI's IA regs /
// MiCA Title V), every consumer-facing surface that returns a score
// must render this disclaimer alongside the numeric output.
//
// This string is mirrored BYTE-FOR-BYTE from
// `phylanx-oracle/oracle/securities_compliance.py` (ADVISORY_DISCLAIMER).
// `audit/securities_compliance_check.py` verifies the two strings
// agree — drift here means the SDK and the Python substrate
// disagree on the public-facing disclosure, which is a legal posture
// risk before it is an engineering bug.

/**
 * The canonical SEC-1 advisory disclaimer.
 *
 * Every consumer integration MUST surface this text at the boundary
 * where a score is returned (in API responses, logs that a user might
 * see, or any UI that renders a Phylanx cert). The integration manifest
 * gate (`audit/consumer_integration_check.py` + the SEC-1 audit gate)
 * verifies the marker is present in the reader source on disk.
 */
export const ADVISORY_DISCLAIMER: string =
  "Phylanx cert scores are technical trust signals computed from " +
  "observable on-chain behaviour. They are NOT investment advice, " +
  "NOT a security rating, and NOT issued by a registered " +
  "investment adviser. Consumers MUST NOT treat a Phylanx cert " +
  "score as a recommendation to buy, sell, or hold any asset; the " +
  "decision to act on the score is the consumer's alone.";

/**
 * Helper for callsites that prefer a function over a constant. Returns
 * `ADVISORY_DISCLAIMER` unchanged.
 */
export function disclaimerText(): string {
  return ADVISORY_DISCLAIMER;
}


// =============================================================================
// AML-1 — KYC/AML disclaimer
// =============================================================================
//
// Large-scale AI agent lending enabled by Phylanx certs may pull
// downstream DeFi protocols into MSB / VASP / reporting-entity
// territory, and an adversarial regulatory complaint against the
// cluster itself is a process-tax attack the protocol must defuse.
// The cluster does not custody value, transmit funds, exchange
// assets, or collect customer identity information — but consumers
// must NOT mistake a cert score for a KYC control or sanctions
// screen.
//
// This string is mirrored BYTE-FOR-BYTE from
// `phylanx-oracle/oracle/aml_compliance.py` (AML_KYC_DISCLAIMER).
// `audit/aml_compliance_check.py` verifies the two strings agree
// — drift here means the SDK and the Python substrate disagree on
// the AML carve-out posture, which is a legal posture risk before
// it is an engineering bug.

/**
 * The canonical AML-1 KYC/AML disclaimer.
 *
 * Every consumer integration MUST surface this text at the boundary
 * where a score is returned (alongside `ADVISORY_DISCLAIMER`). The
 * integration manifest gate (`audit/consumer_integration_check.py`
 * + the AML-1 audit gate) verifies the marker is present in the
 * reader source on disk.
 */
export const AML_KYC_DISCLAIMER: string =
  "Phylanx cert scores are technical trust signals computed from " +
  "observable on-chain behaviour. They are NOT a KYC control, " +
  "NOT an AML screen, and NOT a substitute for the consumer's " +
  "own customer due-diligence, sanctions screening, or Travel " +
  "Rule obligations under applicable law. The Phylanx cluster " +
  "does not collect customer identity information; consumers " +
  "MUST run their own KYC/AML program for any transaction they " +
  "originate or terminate based on a cert score.";

/**
 * Helper for callsites that prefer a function over a constant. Returns
 * `AML_KYC_DISCLAIMER` unchanged.
 */
export function amlKycDisclaimerText(): string {
  return AML_KYC_DISCLAIMER;
}


// =============================================================================
// Result types
// =============================================================================

export enum RejectReason {
  /** Newest cert in the window is older than CERT_MAX_AGE_SECONDS. */
  StaleCert = "STALE_CERT",
  /** max(scores) - min(scores) across the window > MAX_SCORE_VELOCITY. */
  VelocityExceeded = "VELOCITY_EXCEEDED",
  /** Fewer than MIN_HISTORY_REQUIRED certs found in the window. */
  InsufficientHistory = "INSUFFICIENT_HISTORY",
  /** No cert for the current epoch at all. */
  NoCurrentCert = "NO_CURRENT_CERT",
}

export interface SafeScoreOk {
  ok: true;
  /** The current-epoch score (latest cert in the window). */
  score: number;
  /** The current-epoch alert tier. */
  alert: AlertTier;
  /** The epoch the returned score covers. */
  epoch: number;
  /** Unix seconds the returned cert was issued on chain. */
  issuedAt: number;
  /** The (min, max) score envelope observed across the velocity window. */
  velocityWindow: { minScore: number; maxScore: number; epochs: number[] };
}

export interface SafeScoreRejected {
  ok: false;
  reason: RejectReason;
  detail: string;
}

export type SafeScoreResult = SafeScoreOk | SafeScoreRejected;


// =============================================================================
// ChainReader — the minimal PhylanxChainClient surface SafeCertReader needs
// =============================================================================

/**
 * The duck-typed surface the SafeCertReader requires. `PhylanxChainClient`
 * already satisfies this; tests pass a mock without spinning up a
 * validator.
 */
export interface ChainReader {
  getCurrentEpoch(): Promise<number>;
  getScoreHistory(
    agent: PublicKey,
    fromEpoch: number,
    toEpoch: number
  ): Promise<EpochScore[]>;
}


// =============================================================================
// SafeCertReader
// =============================================================================

export interface SafeCertReaderOptions {
  /** Override the wall clock — tests inject a fixed `now` here. */
  nowSeconds?: () => number;
  /**
   * Override CERT_MAX_AGE_SECONDS for the rare consumer with a stricter
   * SLA. Looser values must be justified to the audit — the default is
   * the audit ceiling.
   */
  maxAgeSeconds?: number;
  /** Override MAX_SCORE_VELOCITY. Same caveat as `maxAgeSeconds`. */
  maxVelocity?: number;
  /** Override VELOCITY_WINDOW_EPOCHS. */
  windowEpochs?: number;
}

export class SafeCertReader {
  private readonly chain: ChainReader;
  private readonly nowSeconds: () => number;
  private readonly maxAgeSeconds: number;
  private readonly maxVelocity: number;
  private readonly windowEpochs: number;

  constructor(chain: ChainReader, opts: SafeCertReaderOptions = {}) {
    this.chain = chain;
    this.nowSeconds = opts.nowSeconds ?? (() => Math.floor(Date.now() / 1000));
    this.maxAgeSeconds = opts.maxAgeSeconds ?? CERT_MAX_AGE_SECONDS;
    this.maxVelocity = opts.maxVelocity ?? MAX_SCORE_VELOCITY;
    this.windowEpochs = opts.windowEpochs ?? VELOCITY_WINDOW_EPOCHS;

    if (this.maxAgeSeconds <= 0) {
      throw new Error("maxAgeSeconds must be positive");
    }
    if (this.maxVelocity < 0) {
      throw new Error("maxVelocity must be non-negative");
    }
    if (this.windowEpochs < MIN_HISTORY_REQUIRED) {
      throw new Error(
        `windowEpochs (${this.windowEpochs}) must be >= ${MIN_HISTORY_REQUIRED}`
      );
    }
  }

  /**
   * Return the agent's safe-to-act-on score, or a structured rejection.
   *
   * NEVER throws on a guard-rail trip — rejection is part of the API
   * contract. Network / RPC failures still propagate (the protocol's
   * call site decides whether to retry or fail closed).
   */
  async getSafeScore(agent: PublicKey): Promise<SafeScoreResult> {
    const currentEpoch = await this.chain.getCurrentEpoch();
    // Inclusive window: currentEpoch - (windowEpochs - 1) .. currentEpoch.
    const fromEpoch = Math.max(0, currentEpoch - (this.windowEpochs - 1));

    const history = await this.chain.getScoreHistory(
      agent,
      fromEpoch,
      currentEpoch
    );

    if (history.length < MIN_HISTORY_REQUIRED) {
      return {
        ok: false,
        reason: RejectReason.InsufficientHistory,
        detail:
          `agent ${agent.toBase58()} has ${history.length} cert(s) in epochs ` +
          `${fromEpoch}..${currentEpoch}; need >= ${MIN_HISTORY_REQUIRED} ` +
          `to make a velocity claim`,
      };
    }

    // Sort newest-first by epoch — getScoreHistory is sparse but
    // generally ordered; we don't trust the order.
    const sorted = [...history].sort((a, b) => b.epoch - a.epoch);
    const latest = sorted[0];

    if (latest.epoch !== currentEpoch) {
      return {
        ok: false,
        reason: RejectReason.NoCurrentCert,
        detail:
          `agent ${agent.toBase58()} has no cert for current epoch ` +
          `${currentEpoch}; newest is epoch ${latest.epoch}`,
      };
    }

    const now = this.nowSeconds();
    const ageSeconds = now - latest.issuedAt;
    if (ageSeconds > this.maxAgeSeconds) {
      return {
        ok: false,
        reason: RejectReason.StaleCert,
        detail:
          `cert for agent ${agent.toBase58()} epoch ${latest.epoch} is ` +
          `${ageSeconds}s old (issued_at=${latest.issuedAt}, now=${now}); ` +
          `max ${this.maxAgeSeconds}s`,
      };
    }

    const scores = sorted.map((c) => c.score);
    const minScore = Math.min(...scores);
    const maxScore = Math.max(...scores);
    const velocity = maxScore - minScore;
    if (velocity > this.maxVelocity) {
      return {
        ok: false,
        reason: RejectReason.VelocityExceeded,
        detail:
          `agent ${agent.toBase58()} score swung ${velocity} points across ` +
          `epochs ${sorted[sorted.length - 1].epoch}..${latest.epoch} ` +
          `(min=${minScore}, max=${maxScore}); max ${this.maxVelocity}`,
      };
    }

    return {
      ok: true,
      score: latest.score,
      alert: latest.alert,
      epoch: latest.epoch,
      issuedAt: latest.issuedAt,
      velocityWindow: {
        minScore,
        maxScore,
        epochs: sorted.map((c) => c.epoch).reverse(),
      },
    };
  }
}
