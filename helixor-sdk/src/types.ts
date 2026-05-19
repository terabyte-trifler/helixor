// =============================================================================
// helixor-sdk/src/types.ts — the stable SDK surface.
//
// THE COMPATIBILITY CONTRACT
// --------------------------
// The MVP's SDK exposed `getScore(agent) -> HealthScore`. Day 19 changes
// where that data comes FROM — the score now lives in an epoch-keyed
// HealthCertificate on the certificate-issuer program instead of a single
// overwritten account — but the SDK SHAPE does not change. Existing MVP
// consumers of `getScore` keep working without a code change.
//
// `HealthScore` below is exactly the MVP shape. New V2 capability (epoch
// history) is ADDITIVE — `getScoreHistory`, `getScoreAtEpoch` — never a
// breaking change to `getScore`.
// =============================================================================

import { PublicKey } from "@solana/web3.js";

/**
 * The alert tier. Stable wire codes — 0/1/2 — matching the on-chain
 * AlertTier enum and the off-chain scoring.AlertTier.
 */
export enum AlertTier {
  Green = "GREEN",
  Yellow = "YELLOW",
  Red = "RED",
}

/** Decode the on-chain u8 alert code into the SDK's AlertTier. */
export function alertTierFromCode(code: number): AlertTier {
  switch (code) {
    case 0:
      return AlertTier.Green;
    case 1:
      return AlertTier.Yellow;
    case 2:
      return AlertTier.Red;
    default:
      throw new Error(`invalid alert tier code: ${code}`);
  }
}

/**
 * HealthScore — the MVP-compatible result shape of `getScore`.
 *
 * This interface is FROZEN: it is the public compatibility contract. The
 * fields and their types match what the MVP SDK returned, so any consumer
 * written against the MVP keeps compiling and behaving identically.
 */
export interface HealthScore {
  /** The agent the score is for. */
  agent: PublicKey;
  /** The composite trust score, 0..1000. */
  score: number;
  /** The alert tier. */
  alert: AlertTier;
  /** The aggregated detection flag bits. */
  flags: number;
  /** Unix seconds the score was issued on chain. */
  issuedAt: number;
}

/**
 * Legacy REST/API score shape used by the policy error classes. The on-chain
 * Day-19 SDK surface is `HealthScore`; this type remains so older consumers of
 * the policy helpers still compile while the stable `getScore` shape stays
 * unchanged.
 */
export interface TrustScore {
  agent: string;
  score: number;
  alert: AlertTier;
  updatedAt: number;
  source: string;
  anomalyFlag?: boolean;
  active?: boolean;
  provisional?: boolean;
}

/**
 * EpochScore — a HealthScore for a SPECIFIC epoch. This is the V2 ADDITION:
 * it carries the epoch number. `getScore` still returns the frozen
 * `HealthScore`; callers who want the epoch use the new methods.
 */
export interface EpochScore extends HealthScore {
  /** The epoch this score covers. */
  epoch: number;
  /** Whether the IMMEDIATE_RED security fast-path was tripped. */
  immediateRed: boolean;
}

/** Program IDs the SDK talks to. */
export interface HelixorProgramIds {
  healthOracle: PublicKey;
  certificateIssuer: PublicKey;
}
