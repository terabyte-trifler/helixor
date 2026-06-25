// =============================================================================
// phylanx-sdk — the Phylanx V2 client SDK.
//
// DBP-3 — SAFE BY DEFAULT
// -----------------------
// The default entry point exposes ONLY structurally-safe surfaces:
//   * `SafeCertReader` (VULN-23 freshness + velocity guard)
//   * `verifyInputProvenance` / `verifyAgainstSolanaLedger` (AW-01 / AW-01-EXT)
//   * `verifyBaselineProvenance` / `verifyScoreComputation` (AW-03 / AW-04)
//   * DBP-2 `VerifiedConsumer` helpers
//   * PDA derivation helpers, account decoders, type definitions
//
// Raw cert-reading clients live behind the explicit `@phylanx/sdk/unsafe`
// subpath. A consumer who genuinely needs the raw primitives types the
// word `unsafe` to import them; the DBP-1 linter then verifies they wrap
// the raw client in a safety-checking reader rather than reading it raw.
//
// See `launch/design/defi_bypass_resolution.md` §DBP-3 for the rollout
// and the runbook for the failure modes.
// =============================================================================

// Safe types — shared between the raw clients (in `/unsafe`) and the
// SafeCertReader contract. Exporting AlertTier / HealthScore / EpochScore
// here keeps consumer-side type annotations intact even if they never
// instantiate a raw client.
export {
  AlertTier,
  alertTierFromCode,
  type HealthScore,
  type EpochScore,
  type PhylanxProgramIds,
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
//
// SEC-1 — ADVISORY_DISCLAIMER + disclaimerText are also re-exported here:
// every consumer integration surfaces this text at the boundary where a
// score is returned so the cluster's posture stays as a technical trust
// signal rather than implicit investment advice. The audit gate verifies
// the marker is present in every published integration reader.
//
// AML-1 — AML_KYC_DISCLAIMER + amlKycDisclaimerText are surfaced
// alongside the SEC-1 disclaimer for the same reason: every
// integration must render the not-a-KYC-control / not-an-AML-screen
// posture so a downstream lending protocol cannot misuse the score
// as a substitute for its own customer due-diligence.
export {
  SafeCertReader,
  RejectReason,
  CERT_MAX_AGE_SECONDS,
  MAX_SCORE_VELOCITY,
  VELOCITY_WINDOW_EPOCHS,
  MIN_HISTORY_REQUIRED,
  ADVISORY_DISCLAIMER,
  disclaimerText,
  AML_KYC_DISCLAIMER,
  amlKycDisclaimerText,
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

// Day-40 — Consumer surfaces v2. The diagnosis surface decodes the
// threshold-attested cert v2 fields (per-dimension breakdown, label
// names from the local taxonomy mirror, remediation hints). The evidence
// surface fetches the canonical-JSON payload bound to the on-chain
// `diagnosis_payload_hash` and lets the consumer locally verify
// sha256(payload) == on-chain hash — the "verify without trusting any
// vendor" recipe, in 5 lines.
export {
  getDiagnosis,
  getEvidence,
  verifyEvidenceHash,
  DiagnosisError,
  DiagnosisNotFoundError,
  EvidenceNotFoundError,
  type Diagnosis,
  type DiagnosisAttestation,
  type Evidence,
  type EvidenceAttestation,
  type EvidenceVerification,
  type EvidenceVerificationRecipe,
  type DimensionBreakdown,
  type DecodedLabel,
  type RemediationHint,
  type AlertTierName,
  type DiagnosisFetchOptions,
} from "./diagnosis";

// Day-40 — Generated TS mirror of `phylanx-oracle/diagnosis/taxonomy.json`.
// A consumer that decodes a Diagnosis can resolve label names without a
// network call — the bit→name lookup lives in-process. The
// `TAXONOMY_SCHEMA_VERSION` constant lets a strict consumer assert their
// SDK is at the same taxonomy revision the cluster signed against.
export {
  FAILURE_MODES,
  REMEDIATION_CODES,
  TAXONOMY_SCHEMA_VERSION,
  failureModeByBit,
  failureModeByName,
  failureModeName,
  remediationByBit,
  remediationByName,
  type FailureModeEntry,
  type RemediationEntry,
  type SeverityName,
} from "./taxonomy_generated";

// AW-04 scoring-provenance verification — fetch the on-chain
// ScoreComponentsAccount, recompute sha256(payload), parse the canonical
// JSON, and re-execute the documented scoring formula
// (sum -> clamp -> delta-guard) to confirm it arrives at the published
// `cert.score`. Pairs with `verifyScoringCodeHash`, which checks the
// cert's `scoring_code_hash` against a consumer-supplied expected hash
// derived from cloning the phylanx repo at the published tag. A consumer
// who passes AW-01 + AW-03 + AW-04 has cryptographic proof of EVERY
// trust assumption behind a Phylanx cert.
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
