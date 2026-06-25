// =============================================================================
// example_safe_partner/reader.ts — the canonical "Verified Integrator"
// reference cert-reader.
//
// This file is the REFERENCE IMPLEMENTATION cited by the audit linter
// (`audit/consumer_integration_check.py`). A DeFi partner who copy-pastes
// this file and points their manifest at it is by construction safe along
// every Phylanx-defined axis:
//
//   * VULN-23 freshness + velocity floor (SafeCertReader from @phylanx/sdk)
//   * SOL-3 per-operation freshness contract (loan-issue 4h / loan-increase
//     8h / liquidation 12h / status-read 48h)
//   * AW-01-EXT slot-anchor cross-check (verifyAgainstSolanaLedger)
//
// Path 4 of the red-team attack tree ("DeFi Bypass") is the residual that
// lives ENTIRELY in the consumer's code. Phylanx cannot close it from its
// own substrate — the only durable mitigation is making the safe path the
// easy path. This file IS the safe path: opinionated, no escape hatches,
// no `getScore()` fallback. A consumer that adopts it cannot accidentally
// drain themselves the way the Path-4 attack tree describes.
// =============================================================================

import { Connection, PublicKey } from "@solana/web3.js";

import {
  // VULN-23 — the safe wrapper around any ChainReader. Returns a
  // discriminated `SafeScoreResult`, NEVER a raw score.
  SafeCertReader,
  RejectReason,
  type ChainReader,
  type SafeScoreResult,
  CERT_MAX_AGE_SECONDS,
  MAX_SCORE_VELOCITY,
  // SEC-1 — the canonical advisory disclaimer surfaced alongside every
  // returned score. Mirrored byte-for-byte from
  // phylanx-oracle/oracle/securities_compliance.py.
  ADVISORY_DISCLAIMER,
  // AML-1 — the canonical KYC/AML disclaimer surfaced alongside the
  // SEC-1 disclaimer. Mirrored byte-for-byte from
  // phylanx-oracle/oracle/aml_compliance.py.
  AML_KYC_DISCLAIMER,
  // AW-01-EXT — slot-anchor ledger re-verification.
  verifyAgainstSolanaLedger,
  LedgerRejection,
  type SlotHashesProvider,
  // AW-01 — input-provenance verification (paired with AW-01-EXT).
  verifyInputProvenance,
  ProvenanceRejection,
  type ObservableTransaction,
  // Decoded cert + helper types.
  decodeHealthCertificate,
  type DecodedHealthCertificate,
} from "@phylanx/sdk";


// =============================================================================
// SOL-3 per-operation freshness floors — mirror of
// phylanx-oracle/oracle/operation_freshness.py constants.
//
// These are NOT bumpable knobs. They are the audit-mandated risk-asymmetric
// contract: high-stakes write operations (LOAN_ISSUE) refuse against older
// certs than low-stakes read operations (STATUS_READ). A consumer that
// adopts these floors gates real money behind fresh data.
// =============================================================================

export const LOAN_ISSUE_MAX_AGE_SECONDS = 4 * 60 * 60;
export const LOAN_INCREASE_MAX_AGE_SECONDS = 8 * 60 * 60;
export const LIQUIDATION_CHECK_MAX_AGE_SECONDS = 12 * 60 * 60;
export const STATUS_READ_MAX_AGE_SECONDS = 48 * 60 * 60;
export const OPERATION_FUTURE_TOLERANCE_SECONDS = 60;

export enum Operation {
  LOAN_ISSUE = "LOAN_ISSUE",
  LOAN_INCREASE = "LOAN_INCREASE",
  LIQUIDATION_CHECK = "LIQUIDATION_CHECK",
  STATUS_READ = "STATUS_READ",
}

const OPERATION_MAX_AGE: Record<Operation, number> = {
  [Operation.LOAN_ISSUE]: LOAN_ISSUE_MAX_AGE_SECONDS,
  [Operation.LOAN_INCREASE]: LOAN_INCREASE_MAX_AGE_SECONDS,
  [Operation.LIQUIDATION_CHECK]: LIQUIDATION_CHECK_MAX_AGE_SECONDS,
  [Operation.STATUS_READ]: STATUS_READ_MAX_AGE_SECONDS,
};


// =============================================================================
// Result types
// =============================================================================

export type SafeOperationOk = {
  ok: true;
  operation: Operation;
  score: number;
  alertTier: string;
  epoch: number;
  issuedAt: number;
  certAgeSeconds: number;
  /**
   * SEC-1 — the canonical advisory disclaimer rendered alongside the
   * returned score. Mirrored from
   * `phylanx-oracle/oracle/securities_compliance.py`. Consumer-side UIs /
   * API responses MUST surface this text to the end-user. The audit gate
   * (`audit/securities_compliance_check.py`) verifies this field is
   * populated from the SDK constant — drift here breaks the cluster's
   * posture as a technical trust signal.
   */
  advisoryDisclaimer: string;
  /**
   * AML-1 — the canonical KYC/AML disclaimer rendered alongside the
   * returned score. Mirrored from
   * `phylanx-oracle/oracle/aml_compliance.py`. Consumer-side UIs / API
   * responses MUST surface this text to the end-user so a downstream
   * lending protocol cannot misuse the score as a substitute for its
   * own customer due-diligence. The audit gate
   * (`audit/aml_compliance_check.py`) verifies this field is populated
   * from the SDK constant.
   */
  amlKycDisclaimer: string;
};

export type SafeOperationRejected = {
  ok: false;
  operation: Operation;
  reason:
    | "STALE_FOR_OPERATION"
    | "CERT_IN_FUTURE"
    | "SAFE_READER_REJECTED"
    | "INPUT_PROVENANCE_FAILED"
    | "SLOT_ANCHOR_FAILED";
  detail: string;
};

export type SafeOperationResult = SafeOperationOk | SafeOperationRejected;


// =============================================================================
// The reader
// =============================================================================

export interface SafePartnerReaderOptions {
  /** Solana connection used to fetch the on-chain cert + sysvars. */
  connection: Connection;
  /** SDK ChainReader (PhylanxChainClient or any equivalent). */
  chainReader: ChainReader;
  /** Slot-hashes provider, typically `() => connection.getSlotHashes()`. */
  slotHashesProvider: SlotHashesProvider;
  /** Now-seconds resolver. Defaults to `Date.now()/1000` rounded down. */
  nowSeconds?: () => number;
}

export class SafePartnerReader {
  private readonly conn: Connection;
  private readonly safeReader: SafeCertReader;
  private readonly slotHashes: SlotHashesProvider;
  private readonly now: () => number;
  private readonly chainReader: ChainReader;

  constructor(opts: SafePartnerReaderOptions) {
    this.conn = opts.connection;
    this.safeReader = new SafeCertReader({ chainReader: opts.chainReader });
    this.slotHashes = opts.slotHashesProvider;
    this.now = opts.nowSeconds ?? (() => Math.floor(Date.now() / 1000));
    this.chainReader = opts.chainReader;
  }

  /**
   * Resolve a Phylanx cert for the given agent + operation under the FULL
   * Verified-Integrator contract: VULN-23 + SOL-3 + AW-01 + AW-01-EXT.
   *
   * NEVER fall through to a default-allow on `ok: false` — the whole point
   * of this reader is to make refusal the safe default. If the caller wants
   * "best-effort", they can switch on the `reason` field, but the safe
   * pattern is "refuse the operation".
   */
  async safeOperation(
    agent: PublicKey,
    operation: Operation,
    observedInputs: ObservableTransaction[],
  ): Promise<SafeOperationResult> {
    // ---- VULN-23 — freshness (48h ceiling) + velocity (±200/3 epochs).
    const safe: SafeScoreResult = await this.safeReader.getSafeScore(agent);
    if (!safe.ok) {
      return {
        ok: false,
        operation,
        reason: "SAFE_READER_REJECTED",
        detail: `${safe.reason}: ${safe.detail}`,
      };
    }

    // ---- SOL-3 — per-operation freshness floor. Strictly stricter than
    // VULN-23 for LOAN_ISSUE / LOAN_INCREASE / LIQUIDATION_CHECK.
    const now = this.now();
    const certAge = now - safe.issuedAt;
    if (certAge < -OPERATION_FUTURE_TOLERANCE_SECONDS) {
      return {
        ok: false,
        operation,
        reason: "CERT_IN_FUTURE",
        detail: `cert issuedAt=${safe.issuedAt} > now=${now}`,
      };
    }
    const opCeiling = OPERATION_MAX_AGE[operation];
    if (certAge > opCeiling) {
      return {
        ok: false,
        operation,
        reason: "STALE_FOR_OPERATION",
        detail: `cert age ${certAge}s > ${operation} ceiling ${opCeiling}s`,
      };
    }

    // ---- AW-01 — input-provenance verification. Refuses if the cert's
    // declared inputs don't match what the consumer can observe.
    const cert = await this.fetchDecodedCert(agent);
    const provenance = verifyInputProvenance(cert, observedInputs);
    if (!provenance.ok) {
      return {
        ok: false,
        operation,
        reason: "INPUT_PROVENANCE_FAILED",
        detail: `${ProvenanceRejection[provenance.rejection]}: ${provenance.detail}`,
      };
    }

    // ---- AW-01-EXT — slot-anchor ledger re-verification. Refuses if the
    // cluster's pinned (slot, block_hash) doesn't reproduce against the
    // consumer's INDEPENDENT RPC.
    const ledger = await verifyAgainstSolanaLedger(cert, this.slotHashes);
    if (!ledger.ok) {
      return {
        ok: false,
        operation,
        reason: "SLOT_ANCHOR_FAILED",
        detail: `${LedgerRejection[ledger.rejection]}: ${ledger.detail}`,
      };
    }

    // All four gates passed. Safe to act on the score.
    return {
      ok: true,
      operation,
      score: safe.score,
      alertTier: String(safe.alert),
      epoch: safe.epoch,
      issuedAt: safe.issuedAt,
      certAgeSeconds: certAge,
      // SEC-1 — surface the canonical disclaimer alongside every
      // returned score so the consumer's UI / API response carries the
      // not-investment-advice posture verbatim.
      advisoryDisclaimer: ADVISORY_DISCLAIMER,
      // AML-1 — surface the KYC/AML carve-out so the consumer cannot
      // treat the score as a substitute for their own KYC / sanctions
      // screening / Travel Rule obligations.
      amlKycDisclaimer: AML_KYC_DISCLAIMER,
    };
  }

  private async fetchDecodedCert(
    agent: PublicKey,
  ): Promise<DecodedHealthCertificate> {
    // Implementation detail: defers to whatever ChainReader the partner
    // wired. The contract is "decode a cert into DecodedHealthCertificate".
    return await this.chainReader.fetchDecodedCertificate(agent);
  }
}


// =============================================================================
// Convenience helpers — the "one-liner" surface for partners who don't
// need to hold a reader instance.
// =============================================================================

/**
 * Resolve a cert for the given (agent, operation) using the full Verified
 * Integrator contract. Convenience wrapper around `SafePartnerReader`.
 */
export async function safeReadForOperation(
  agent: PublicKey,
  operation: Operation,
  opts: SafePartnerReaderOptions & { observedInputs: ObservableTransaction[] },
): Promise<SafeOperationResult> {
  const reader = new SafePartnerReader(opts);
  return reader.safeOperation(agent, operation, opts.observedInputs);
}


// Re-export the underlying reject reason enum so callers can switch on the
// VULN-23 layer's reason without a separate import.
export { RejectReason, CERT_MAX_AGE_SECONDS, MAX_SCORE_VELOCITY };
