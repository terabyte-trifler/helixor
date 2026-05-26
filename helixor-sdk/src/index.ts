// =============================================================================
// helixor-sdk — the Helixor V2 client SDK.
//
// `getScore` is the MVP-compatible entry point — same shape, new on-chain
// source. Everything else (epoch history) is additive.
// =============================================================================

// HTTP REST client (used by the ElizaOS plugin and off-chain consumers)
export {
  HelixorClient,
  HelixorError,
  AgentNotFoundError,
  type TrustScore,
  type RequireMinScoreOptions,
} from "./http_client";

// On-chain Solana client (reads certificates directly from the chain)
export {
  HelixorChainClient,
  CertificateNotFoundError,
} from "./client";
export {
  AlertTier,
  alertTierFromCode,
  type HealthScore,
  type EpochScore,
  type HelixorProgramIds,
} from "./types";
export {
  certificatePda,
  baselineStatsPda,
  issuerConfigPda,
  epochStatePda,
  epochToLeBytes,
  baselineDataPda,
  commitNonceToLeBytes,
  scoreComponentsPda,
} from "./pdas";

// DBP-2 — on-chain "Verified Integrator" badge. Downstream lending
// contracts gate access on `isActive(decoded)` over the per-partner PDA.
// Presence alone is NOT sufficient — revoked badges persist on chain so
// "had a badge, lost it" is distinguishable from "never had a badge."
export {
  verifiedConsumerPda,
  decodeVerifiedConsumer,
  fetchVerifiedConsumer,
  registrationAttestationDigest,
  isActive as isVerifiedConsumerActive,
  VerifiedConsumerState,
  RevokeReason,
  REGISTRATION_DOMAIN_TAG,
  type DecodedVerifiedConsumer,
} from "./verified_consumer";
export {
  decodeHealthCertificate,
  decodeEpochState,
  decodeBaselineDataAccount,
  decodeScoreComponentsAccount,
  type DecodedHealthCertificate,
  type DecodedEpochState,
  type DecodedBaselineDataAccount,
  type DecodedScoreComponentsAccount,
} from "./decode";

// VULN-23 consumer-side guard rails — wraps any ChainReader and refuses
// stale or velocity-pumped certs before a DeFi protocol acts on them.
export {
  SafeCertReader,
  RejectReason,
  CERT_MAX_AGE_SECONDS,
  MAX_SCORE_VELOCITY,
  VELOCITY_WINDOW_EPOCHS,
  MIN_HISTORY_REQUIRED,
  type ChainReader,
  type SafeCertReaderOptions,
  type SafeScoreOk,
  type SafeScoreRejected,
  type SafeScoreResult,
} from "./safe_reader";

// AW-02 epoch-advance digest — cluster operators compute this exactly the
// way the on-chain verifier does, sign with their cluster keypair, and
// attach the resulting Ed25519 program instruction to the advance_epoch tx.
export {
  ADVANCE_EPOCH_DOMAIN_TAG,
  advancePayloadDigest,
} from "./advance_epoch";

// AW-01 input-provenance verification — recompute the cluster's input
// commitment from observable transactions and refuse certs whose declared
// inputs do not match what the consumer sees on chain.
//
// AW-01-EXT extends this with a Solana slot-anchor: the cluster pins a
// `(slot, block_hash)` at scoring time, the on-chain handler verifies it
// against `SlotHashes`, and `verifyAgainstSolanaLedger` lets a consumer
// re-run the same check off-chain.
export {
  computeInputCommitment,
  verifyInputProvenance,
  verifyAgainstSolanaLedger,
  ProvenanceRejection,
  LedgerRejection,
  COMMITMENT_BYTES,
  INPUT_COMMITMENT_VERSION,
  SLOT_ANCHOR_BYTES,
  type ObservableTransaction,
  type ExtractionWindow,
  type InputCommitmentInputs,
  type ProvenanceResult,
  type SlotAnchor,
  type SolanaLedgerVerification,
  type SlotHashesProvider,
} from "./input_provenance";

// AW-03 baseline-provenance verification — fetch the on-chain DA account,
// recompute sha256(payload), and assert == cert.baselineHash. A consumer
// who passes both verifyInputProvenance + verifyBaselineProvenance has
// cryptographic proof of EVERY input behind the score: the observable
// transactions (AW-01) and the statistical baseline they were scored
// against (AW-03).
export {
  verifyBaselineProvenance,
  sha256Payload,
  decodeBaselinePayload,
  BaselineProvenanceRejection,
  type BaselineProvenanceOk,
  type BaselineProvenanceFail,
  type BaselineProvenanceResult,
  type ParsedBaselinePayload,
} from "./baseline_provenance";

// AW-04 scoring-provenance verification — fetch the on-chain
// ScoreComponentsAccount, recompute sha256(payload), parse the canonical
// JSON, and re-execute the documented scoring formula
// (sum -> clamp -> delta-guard) to confirm it arrives at the published
// `cert.score`. Pairs with `verifyScoringCodeHash`, which checks the
// cert's `scoring_code_hash` against a consumer-supplied expected hash
// derived from cloning the helixor repo at the published tag. A consumer
// who passes AW-01 + AW-03 + AW-04 has cryptographic proof of EVERY
// trust assumption behind a Helixor cert.
export {
  verifyScoreComputation,
  verifyScoringCodeHash,
  replayScoreFromComponents,
  parseScoreComponentsPayload,
  sha256ComponentsPayload,
  ScoringProvenanceRejection,
  CodeHashCheckResult,
  SCORE_COMPONENTS_SCHEMA_VERSION,
  MAX_SCORE_COMPONENTS_PAYLOAD_LEN,
  MAX_SCORE_DELTA,
  SCORE_MIN,
  SCORE_MAX,
  type ScoringProvenanceOk,
  type ScoringProvenanceFail,
  type ScoringProvenanceResult,
  type ParsedScoreComponents,
  type ScoreComponentsDim,
  type ScoreReplay,
  type CodeHashCheck,
} from "./scoring_provenance";
