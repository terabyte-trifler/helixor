// =============================================================================
// helixor-sdk/src/diagnosis.ts — Day-40 Consumer surfaces v2.
//
// `getDiagnosis(apiBase, agent, epoch)` returns the structured cert-v2
// diagnosis the cluster threshold-signs. The decoded surface carries:
//   * the per-dimension breakdown
//   * the legacy u32 flag bitmask AND the human-readable label set
//     resolved via the generated TS mirror of taxonomy.json
//   * an `attestation` discriminator the consumer MUST switch on
//
// `getEvidence(apiBase, agent, epoch)` returns the canonical-JSON
// evidence payload bound to the on-chain `diagnosis_payload_hash`. A
// consumer recomputes sha256 over `payloadCanonicalJson` and checks it
// equals `onChainHashHex` — this is the "verify without trusting any
// vendor" recipe.
//
// `verifyEvidenceHash(evidence)` is the recipe itself. Five lines:
//
//     const ev = await getEvidence(apiBase, agent, epoch);
//     const ok = await verifyEvidenceHash(ev);
//     if (!ok.attested)        throw new Error("cert v2 hash not observed");
//     if (!ok.bytesMatchHash)  throw new Error("vendor tampered with bytes");
//     // … score now has cryptographic provenance to the on-chain cert.
// =============================================================================

import {
  failureModeByBit,
  type SeverityName,
} from "./taxonomy_generated";

// ---------------------------------------------------------------------------
// Types — the decoded SDK surface
// ---------------------------------------------------------------------------

/**
 * Attestation tier of a diagnosis response.
 *  - `"off_chain_v1"`: Day-34 Phase-1 — faithful to the oracle's epoch
 *    output but NOT threshold-signed. A consumer that requires attested
 *    diagnosis MUST wait for `"cert_v2"`.
 *  - `"cert_v2"`: same field set, lifted into a cluster-threshold-signed
 *    certificate (Phase-2).
 */
export type DiagnosisAttestation = "off_chain_v1" | "cert_v2";

/**
 * Attestation tier of an evidence-DA response.
 *  - `"off_chain_v1"`: bytes are faithfully served from the DA store but
 *    no on-chain cert v2 hash has been observed yet, OR the observed
 *    hash does not match these bytes (the latter is a divergence signal
 *    a verifier MUST refuse).
 *  - `"threshold_attested"`: the indexer has observed a cert v2 hash for
 *    this (agent, epoch) AND it matches sha256(payloadCanonicalJson).
 */
export type EvidenceAttestation = "off_chain_v1" | "threshold_attested";

export type AlertTierName = "GREEN" | "YELLOW" | "RED";

export interface DimensionBreakdown {
  dimension:        string;
  score:            number;
  maxScore:         number;
  scoreNormalised:  number;
  flags:            number;
  subScores:        Record<string, number>;
  algoVersion:      number;
}

/**
 * One decoded legacy-bit label. Resolved against the SDK's local
 * taxonomy mirror — if the server's `decoded_labels` carries a name the
 * SDK does not know, the name is passed through but `taxonomyKnown` is
 * `false` so a strict consumer can refuse to attest on an unknown bit.
 */
export interface DecodedLabel {
  name:           string;
  bit:            number;
  description:    string;
  severity:       SeverityName;
  owaspRefs:      string[];
  /** `true` if this bit resolves to an entry in the SDK's bundled taxonomy. */
  taxonomyKnown:  boolean;
}

export interface RemediationHint {
  name: string;
  bit:  number;
}

export interface Diagnosis {
  attestation:           DiagnosisAttestation;
  schemaVersion:         number;
  agentWallet:           string;
  epoch:                 number;
  score:                 number;
  alertTier:             AlertTierName;
  alertTierCode:         0 | 1 | 2;
  immediateRed:          boolean;
  dimensions:            DimensionBreakdown[];
  weightedContributions: Record<string, number>;
  flags:                 number;
  decodedLabels:         DecodedLabel[];
  undecodedFlagBits:     number[];
  remediationHints:      RemediationHint[];
  aggregateSeverity:     SeverityName;
  confidence:            number;
  gamingDetected:        boolean;
  gamingDropFraction:    number;
  deltaClamped:          boolean;
  scoringAlgoVersion:    number;
  scoringWeightsVersion: number;
  scoringSchemaFingerprint: string;
  baselineStatsHash:     string;
  computedAt:            Date;
}

export interface EvidenceVerificationRecipe {
  hashAlgo:   string;
  hashInput:  string;
  jsonDumper: string;
}

export interface Evidence {
  attestation:           EvidenceAttestation;
  schemaVersion:         number;
  agentWallet:           string;
  epoch:                 number;
  taxonomyVersion:       number;
  signerCount:           number;
  payloadCanonicalJson:  string;
  payloadHashHex:        string;
  onChainHashHex:        string | null;
  verification:          EvidenceVerificationRecipe;
  computedAt:            Date;
}

/**
 * Outcome of `verifyEvidenceHash`. The two booleans are independent so a
 * consumer can distinguish "we haven't seen the cert yet" (attested=false,
 * bytesMatchHash=true: served bytes hash to the locally-computed value;
 * just no on-chain anchor yet) from "vendor tampered" (attested=true,
 * bytesMatchHash=false: cert observed but bytes do not match it).
 */
export interface EvidenceVerification {
  /** sha256(payloadCanonicalJson), hex. The hash the consumer locally computes. */
  recomputedHashHex:    string;
  /** Matches what the server reported as the payload hash. */
  bytesMatchHash:       boolean;
  /**
   * `true` iff `onChainHashHex` is not null AND equals the recomputed
   * hash. This is the strict "cryptographically bound to cert v2" gate.
   */
  attested:             boolean;
  /** Convenience: the server's `attestation` field, passed through. */
  serverAttestation:    EvidenceAttestation;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class DiagnosisError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = "DiagnosisError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class DiagnosisNotFoundError extends DiagnosisError {
  constructor(agent: string, epoch: number) {
    super("DIAGNOSIS_NOT_FOUND", `no diagnosis for ${agent} at epoch ${epoch}`);
    this.name = "DiagnosisNotFoundError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class EvidenceNotFoundError extends DiagnosisError {
  constructor(agent: string, epoch: number) {
    super("EVIDENCE_NOT_FOUND", `no evidence payload for ${agent} at epoch ${epoch}`);
    this.name = "EvidenceNotFoundError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/**
 * fetch impl override + optional API key.
 * `fetchImpl` is taken so the SDK works under Node (>=18 has fetch),
 * browsers, and edge runtimes without bundling a polyfill.
 */
export interface DiagnosisFetchOptions {
  fetchImpl?: typeof fetch;
  apiKey?:    string;
  /** Per-request timeout in ms. Default 10_000. */
  timeoutMs?: number;
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async function _get(
  apiBase: string,
  path:    string,
  opts:    DiagnosisFetchOptions,
): Promise<unknown> {
  const url = `${apiBase.replace(/\/$/, "")}${path}`;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.apiKey) headers["X-API-Key"] = opts.apiKey;
  const f = opts.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 10_000);
  let res: Response;
  try {
    res = await f(url, { headers, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
  if (res.status === 404) {
    throw new DiagnosisError("NOT_FOUND", `404 ${path}`);
  }
  if (!res.ok) {
    throw new DiagnosisError(
      "NETWORK_ERROR",
      `HTTP ${res.status} from ${url}`,
    );
  }
  return await res.json();
}

// ---------------------------------------------------------------------------
// Decoders — wire (snake_case) → SDK (camelCase)
// ---------------------------------------------------------------------------

function _decodeDimensions(raw: unknown): DimensionBreakdown[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((d: any) => ({
    dimension:       String(d.dimension ?? ""),
    score:           Number(d.score ?? 0),
    maxScore:        Number(d.max_score ?? 0),
    scoreNormalised: Number(d.score_normalised ?? 0),
    flags:           Number(d.flags ?? 0),
    subScores:       (d.sub_scores ?? {}) as Record<string, number>,
    algoVersion:     Number(d.algo_version ?? 0),
  }));
}

function _decodeLabels(raw: unknown): DecodedLabel[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((l: any) => {
    const bit = Number(l.bit ?? -1);
    const known = failureModeByBit(bit);
    return {
      name:          String(l.name ?? ""),
      bit,
      description:   String(l.description ?? ""),
      severity:      (l.severity ?? "INFO") as SeverityName,
      owaspRefs:     Array.isArray(l.owasp_refs) ? l.owasp_refs.map(String) : [],
      taxonomyKnown: known !== undefined && known.name === String(l.name ?? ""),
    };
  });
}

function _decodeDiagnosis(raw: any): Diagnosis {
  return {
    attestation:              (raw.attestation ?? "off_chain_v1") as DiagnosisAttestation,
    schemaVersion:            Number(raw._v ?? raw.schema_version ?? 0),
    agentWallet:              String(raw.agent_wallet ?? ""),
    epoch:                    Number(raw.epoch ?? 0),
    score:                    Number(raw.score ?? 0),
    alertTier:                (raw.alert_tier ?? "RED") as AlertTierName,
    alertTierCode:            Number(raw.alert_tier_code ?? 2) as 0 | 1 | 2,
    immediateRed:             Boolean(raw.immediate_red ?? false),
    dimensions:               _decodeDimensions(raw.dimensions),
    weightedContributions:    (raw.weighted_contributions ?? {}) as Record<string, number>,
    flags:                    Number(raw.flags ?? 0),
    decodedLabels:            _decodeLabels(raw.decoded_labels),
    undecodedFlagBits:        Array.isArray(raw.undecoded_flag_bits)
                                ? raw.undecoded_flag_bits.map(Number)
                                : [],
    remediationHints:         Array.isArray(raw.remediation_hints)
                                ? raw.remediation_hints.map((r: any) => ({
                                    name: String(r.name ?? ""),
                                    bit:  Number(r.bit ?? -1),
                                  }))
                                : [],
    aggregateSeverity:        (raw.aggregate_severity ?? "INFO") as SeverityName,
    confidence:               Number(raw.confidence ?? 0),
    gamingDetected:           Boolean(raw.gaming_detected ?? false),
    gamingDropFraction:       Number(raw.gaming_drop_fraction ?? 0),
    deltaClamped:             Boolean(raw.delta_clamped ?? false),
    scoringAlgoVersion:       Number(raw.scoring_algo_version ?? 0),
    scoringWeightsVersion:    Number(raw.scoring_weights_version ?? 0),
    scoringSchemaFingerprint: String(raw.scoring_schema_fingerprint ?? ""),
    baselineStatsHash:        String(raw.baseline_stats_hash ?? ""),
    computedAt:               new Date(String(raw.computed_at ?? 0)),
  };
}

function _decodeEvidence(raw: any): Evidence {
  return {
    attestation:           (raw.attestation ?? "off_chain_v1") as EvidenceAttestation,
    schemaVersion:         Number(raw._v ?? raw.schema_version ?? 0),
    agentWallet:           String(raw.agent_wallet ?? ""),
    epoch:                 Number(raw.epoch ?? 0),
    taxonomyVersion:       Number(raw.taxonomy_version ?? 0),
    signerCount:           Number(raw.signer_count ?? 0),
    payloadCanonicalJson:  String(raw.payload_canonical_json ?? ""),
    payloadHashHex:        String(raw.payload_hash_hex ?? ""),
    onChainHashHex:        raw.on_chain_hash_hex == null ? null : String(raw.on_chain_hash_hex),
    verification: {
      hashAlgo:   String(raw.verification?.hash_algo   ?? "sha256"),
      hashInput:  String(raw.verification?.hash_input  ?? "payload_canonical_json"),
      jsonDumper: String(raw.verification?.json_dumper ?? ""),
    },
    computedAt:            new Date(String(raw.computed_at ?? 0)),
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Fetch + decode the cert-v2 diagnosis for `(agent, epoch)`.
 *
 * The returned `Diagnosis` carries the threshold-signed cert fields
 * (when `attestation === "cert_v2"`) or the Day-34 off-chain mirror
 * (`attestation === "off_chain_v1"`). Either way, the consumer reads
 * the same shape — only the trust tier differs.
 *
 * `decodedLabels` carries the human-readable label names already; the
 * `taxonomyKnown` flag lets a consumer assert their bundled SDK
 * recognises every bit before acting on the diagnosis.
 */
export async function getDiagnosis(
  apiBase: string,
  agentWallet: string,
  epoch: number,
  opts: DiagnosisFetchOptions = {},
): Promise<Diagnosis> {
  if (epoch < 1) throw new DiagnosisError("INVALID_EPOCH", `epoch must be >= 1`);
  try {
    const raw = await _get(
      apiBase,
      `/agents/${agentWallet}/diagnosis/${epoch}`,
      opts,
    );
    return _decodeDiagnosis(raw);
  } catch (err) {
    if (err instanceof DiagnosisError && err.code === "NOT_FOUND") {
      throw new DiagnosisNotFoundError(agentWallet, epoch);
    }
    throw err;
  }
}

/**
 * Fetch the canonical-JSON evidence-DA payload bound to the cert v2
 * `diagnosis_payload_hash`. The returned `payloadCanonicalJson` is the
 * EXACT bytes the cluster signed against — a consumer who reproduces
 * the documented dumper can recompute sha256 and verify it lands on
 * `onChainHashHex` without trusting the server.
 *
 * Pair with `verifyEvidenceHash` for the 5-line verification recipe.
 */
export async function getEvidence(
  apiBase: string,
  agentWallet: string,
  epoch: number,
  opts: DiagnosisFetchOptions = {},
): Promise<Evidence> {
  if (epoch < 1) throw new DiagnosisError("INVALID_EPOCH", `epoch must be >= 1`);
  try {
    const raw = await _get(
      apiBase,
      `/agents/${agentWallet}/diagnosis/${epoch}/evidence`,
      opts,
    );
    return _decodeEvidence(raw);
  } catch (err) {
    if (err instanceof DiagnosisError && err.code === "NOT_FOUND") {
      throw new EvidenceNotFoundError(agentWallet, epoch);
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Hash verification — the "verify without trusting any vendor" recipe
// ---------------------------------------------------------------------------

/**
 * Recompute sha256(payloadCanonicalJson) and check it lines up with the
 * server's reported hash AND (if seen) the on-chain cert v2 hash.
 *
 * Why the SDK does the hashing
 * ----------------------------
 * If the consumer trusts the server to do the hashing, the whole DA
 * round-trip collapses — the server could lie about both the bytes and
 * the hash. The SDK hashes the bytes locally so the consumer's audit
 * chain bottoms out at the on-chain hash, not the server.
 */
export async function verifyEvidenceHash(
  evidence: Evidence,
): Promise<EvidenceVerification> {
  const recomputedHashHex = await _sha256Hex(evidence.payloadCanonicalJson);
  const bytesMatchHash = recomputedHashHex === evidence.payloadHashHex.toLowerCase();
  const onChain = (evidence.onChainHashHex ?? "").toLowerCase();
  const attested = onChain.length > 0 && recomputedHashHex === onChain;
  return {
    recomputedHashHex,
    bytesMatchHash,
    attested,
    serverAttestation: evidence.attestation,
  };
}

async function _sha256Hex(input: string): Promise<string> {
  // Two paths so the SDK works in Node (>=18 has WebCrypto on
  // globalThis.crypto.subtle) AND browsers/edge without bundling
  // a polyfill.
  const enc = new TextEncoder();
  const bytes = enc.encode(input);
  const subtle: SubtleCrypto | undefined =
    (globalThis as any).crypto?.subtle ?? undefined;
  if (subtle !== undefined) {
    const digest = await subtle.digest("SHA-256", bytes);
    return _bytesToHex(new Uint8Array(digest));
  }
  // Node <19 fallback — `node:crypto` is always present in Node.
  const nodeCrypto = await import("node:crypto");
  const hash = nodeCrypto.createHash("sha256");
  hash.update(bytes);
  return hash.digest("hex");
}

function _bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
}

// ---------------------------------------------------------------------------
// Convenience: failure-mode + remediation lookups exported from the
// taxonomy mirror, so consumers reading a Diagnosis don't have to import
// from two places.
// ---------------------------------------------------------------------------

export {
  failureModeByBit,
  failureModeByName,
  failureModeName,
  remediationByBit,
  remediationByName,
  FAILURE_MODES,
  REMEDIATION_CODES,
  TAXONOMY_SCHEMA_VERSION,
  type FailureModeEntry,
  type RemediationEntry,
  type SeverityName,
} from "./taxonomy_generated";
