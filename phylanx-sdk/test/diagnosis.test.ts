// =============================================================================
// test/diagnosis.test.ts — Day-40 Consumer surfaces v2.
//
// Covers:
//   * `getDiagnosis(apiBase, agent, epoch)` decodes the v2 cert wire
//     shape (snake_case → camelCase, label decode through the bundled
//     taxonomy).
//   * `getEvidence(...)` decodes the canonical-JSON evidence response.
//   * `verifyEvidenceHash(evidence)` is the "verify without trusting any
//     vendor" recipe — it recomputes sha256 over the served bytes and
//     asserts they match `onChainHashHex`.
//   * Taxonomy mirror integrity — every known failure-mode bit a label
//     can carry resolves to a bundled entry (so `taxonomyKnown` is
//     deterministic).
//
// Uses a fake `fetch` so no validator or live API process is needed.
//
// Run: tsx test/diagnosis.test.ts
// =============================================================================

import * as assert from "assert";
import { createHash } from "node:crypto";

import {
  getDiagnosis,
  getEvidence,
  verifyEvidenceHash,
  DiagnosisNotFoundError,
  EvidenceNotFoundError,
  FAILURE_MODES,
  failureModeByBit,
  failureModeName,
  TAXONOMY_SCHEMA_VERSION,
  type Diagnosis,
  type Evidence,
} from "../src/index";

let passed = 0;
async function test(name: string, fn: () => Promise<void> | void): Promise<void> {
  try {
    await fn();
    passed++;
    console.log(`  ok  ${name}`);
  } catch (err) {
    console.error(`FAIL  ${name}`);
    console.error(err);
    process.exitCode = 1;
  }
}

async function main(): Promise<void> {

// =============================================================================
// Fixtures — wire-shape responses the API actually emits
// =============================================================================

const WALLET = "A1".repeat(22);
const REF_TS = "2026-05-01T12:00:00+00:00";

function diagnosisWire(opts: {
  schemaVersion?: number;
  attestation?: "off_chain_v1" | "cert_v2";
  flags?: number;
  decodedLabels?: Array<{ name: string; bit: number; severity: string }>;
}): object {
  return {
    _v: opts.schemaVersion ?? 2,
    attestation: opts.attestation ?? "cert_v2",
    agent_wallet: WALLET,
    epoch: 29,
    score: 920,
    alert_tier: "GREEN",
    alert_tier_code: 0,
    immediate_red: false,
    dimensions: [
      {
        dimension: "alignment",
        score: 920,
        max_score: 1000,
        score_normalised: 0.92,
        flags: 0,
        sub_scores: { drift: 0.0 },
        algo_version: 1,
      },
    ],
    weighted_contributions: { alignment: 920 },
    flags: opts.flags ?? 0,
    decoded_labels: (opts.decodedLabels ?? []).map((l) => ({
      name: l.name,
      bit:  l.bit,
      description: "decoded label",
      severity: l.severity,
      owasp_refs: [],
    })),
    undecoded_flag_bits: [],
    remediation_hints: [],
    aggregate_severity: "INFO",
    confidence: 900,
    gaming_detected: false,
    gaming_drop_fraction: 0.0,
    delta_clamped: false,
    scoring_algo_version: 1,
    scoring_weights_version: 1,
    scoring_schema_fingerprint: "a".repeat(64),
    baseline_stats_hash: "b".repeat(64),
    computed_at: REF_TS,
  };
}

function evidenceWire(opts: {
  payload?: string;
  onChainHashHex?: string | null;
  attestation?: "off_chain_v1" | "threshold_attested";
  schemaVersion?: number;
}): object {
  // Build a canonical-JSON payload the way the oracle would.
  const payload = opts.payload ?? JSON.stringify(
    {
      taxonomy_version: "1",
      kernel_manifest: "a".repeat(64),
      dimensions: [],
      findings: [],
    },
    // JSON.stringify doesn't sort keys by default — but for the SDK
    // hash-verify test we only need the recomputed digest to match the
    // payload that comes back; the canonical-JSON property is enforced
    // server-side and the SDK just hashes the served bytes verbatim.
  );
  const payloadHashHex = createHash("sha256").update(payload).digest("hex");
  const onChainHashHex = opts.onChainHashHex !== undefined
    ? opts.onChainHashHex
    : payloadHashHex; // default: chain agrees with served bytes
  const attestation = opts.attestation
    ?? (onChainHashHex === payloadHashHex ? "threshold_attested" : "off_chain_v1");
  return {
    _v: opts.schemaVersion ?? 2,
    attestation,
    agent_wallet: WALLET,
    epoch: 29,
    taxonomy_version: 1,
    signer_count: 5,
    payload_canonical_json: payload,
    payload_hash_hex: payloadHashHex,
    on_chain_hash_hex: onChainHashHex,
    verification: {
      hash_algo: "sha256",
      hash_input: "payload_canonical_json",
      json_dumper:
        'json.dumps(payload, sort_keys=True, separators=(",",":"), ensure_ascii=True)',
    },
    computed_at: REF_TS,
  };
}

// =============================================================================
// A FakeFetch that records URLs and returns canned responses
// =============================================================================

interface FakeResponse {
  status:  number;
  json?:   object;
}

function makeFetch(routes: Record<string, FakeResponse>): {
  fetchImpl: typeof fetch;
  calls:     string[];
} {
  const calls: string[] = [];
  const fetchImpl = (async (input: any) => {
    const url = typeof input === "string" ? input : (input as URL).toString();
    calls.push(url);
    for (const [pathFragment, resp] of Object.entries(routes)) {
      if (url.includes(pathFragment)) {
        return {
          status: resp.status,
          ok:     resp.status >= 200 && resp.status < 300,
          json:   async () => resp.json ?? {},
        } as Response;
      }
    }
    return { status: 404, ok: false, json: async () => ({}) } as Response;
  }) as typeof fetch;
  return { fetchImpl, calls };
}

// =============================================================================
// A — getDiagnosis: wire shape → SDK shape
// =============================================================================

await test("getDiagnosis decodes v2 cert fields", async () => {
  const wire = diagnosisWire({
    flags: 1 << 32, // PROMPT_INJECTION
    decodedLabels: [{ name: "PROMPT_INJECTION", bit: 32, severity: "HIGH" }],
  });
  const { fetchImpl } = makeFetch({
    "/agents/": { status: 200, json: wire },
  });
  const diag = await getDiagnosis("http://api.test", WALLET, 29, { fetchImpl });
  assert.strictEqual(diag.attestation, "cert_v2");
  assert.strictEqual(diag.schemaVersion, 2);
  assert.strictEqual(diag.agentWallet, WALLET);
  assert.strictEqual(diag.epoch, 29);
  assert.strictEqual(diag.score, 920);
  assert.strictEqual(diag.alertTier, "GREEN");
  assert.strictEqual(diag.alertTierCode, 0);
  assert.strictEqual(diag.dimensions.length, 1);
  assert.strictEqual(diag.dimensions[0]!.dimension, "alignment");
  assert.strictEqual(diag.dimensions[0]!.scoreNormalised, 0.92);
  assert.strictEqual(diag.decodedLabels.length, 1);
  assert.strictEqual(diag.decodedLabels[0]!.name, "PROMPT_INJECTION");
  assert.strictEqual(diag.decodedLabels[0]!.taxonomyKnown, true);
});

await test("getDiagnosis decoded label with unknown bit → taxonomyKnown=false", async () => {
  const wire = diagnosisWire({
    decodedLabels: [{ name: "NEW_FUTURE_MODE", bit: 63, severity: "MED" }],
  });
  const { fetchImpl } = makeFetch({
    "/agents/": { status: 200, json: wire },
  });
  const diag = await getDiagnosis("http://api.test", WALLET, 29, { fetchImpl });
  assert.strictEqual(diag.decodedLabels[0]!.taxonomyKnown, false);
  // Name is still passed through — strict consumer can decide.
  assert.strictEqual(diag.decodedLabels[0]!.name, "NEW_FUTURE_MODE");
});

await test("getDiagnosis 404 → DiagnosisNotFoundError", async () => {
  const { fetchImpl } = makeFetch({
    "/agents/": { status: 404 },
  });
  await assert.rejects(
    () => getDiagnosis("http://api.test", WALLET, 29, { fetchImpl }),
    DiagnosisNotFoundError,
  );
});

await test("getDiagnosis rejects epoch < 1", async () => {
  await assert.rejects(
    () => getDiagnosis("http://api.test", WALLET, 0, { fetchImpl: makeFetch({}).fetchImpl }),
    /epoch/,
  );
});

await test("getDiagnosis builds correct URL", async () => {
  const wire = diagnosisWire({});
  const { fetchImpl, calls } = makeFetch({
    "/agents/": { status: 200, json: wire },
  });
  await getDiagnosis("http://api.test/", WALLET, 29, { fetchImpl });
  assert.strictEqual(calls.length, 1);
  assert.strictEqual(
    calls[0],
    `http://api.test/agents/${WALLET}/diagnosis/29`,
    "trailing slash on apiBase must be stripped",
  );
});

// =============================================================================
// B — getEvidence + hash verification
// =============================================================================

await test("getEvidence decodes wire shape", async () => {
  const wire = evidenceWire({});
  const { fetchImpl } = makeFetch({
    "/evidence": { status: 200, json: wire },
  });
  const ev = await getEvidence("http://api.test", WALLET, 29, { fetchImpl });
  assert.strictEqual(ev.attestation, "threshold_attested");
  assert.strictEqual(ev.taxonomyVersion, 1);
  assert.strictEqual(ev.signerCount, 5);
  assert.strictEqual(typeof ev.payloadCanonicalJson, "string");
  assert.strictEqual(ev.payloadHashHex.length, 64);
  assert.strictEqual(ev.verification.hashAlgo, "sha256");
});

await test("verifyEvidenceHash — bytes match AND on-chain matches → attested", async () => {
  const wire = evidenceWire({});
  const { fetchImpl } = makeFetch({
    "/evidence": { status: 200, json: wire },
  });
  const ev = await getEvidence("http://api.test", WALLET, 29, { fetchImpl });
  const verdict = await verifyEvidenceHash(ev);
  assert.strictEqual(verdict.bytesMatchHash, true);
  assert.strictEqual(verdict.attested, true);
  assert.strictEqual(verdict.recomputedHashHex, ev.payloadHashHex);
});

await test("verifyEvidenceHash — vendor tampered with bytes → bytesMatchHash=false", async () => {
  const wire: any = evidenceWire({});
  // Vendor lies: the served bytes are not what the server's payload_hash_hex
  // says they are.
  wire.payload_canonical_json = '{"taxonomy_version":"1","tampered":true}';
  const { fetchImpl } = makeFetch({
    "/evidence": { status: 200, json: wire },
  });
  const ev = await getEvidence("http://api.test", WALLET, 29, { fetchImpl });
  const verdict = await verifyEvidenceHash(ev);
  assert.strictEqual(verdict.bytesMatchHash, false);
  assert.strictEqual(verdict.attested, false);
});

await test("verifyEvidenceHash — bytes match but no on-chain anchor yet → attested=false", async () => {
  const wire = evidenceWire({ onChainHashHex: null, attestation: "off_chain_v1" });
  const { fetchImpl } = makeFetch({
    "/evidence": { status: 200, json: wire },
  });
  const ev = await getEvidence("http://api.test", WALLET, 29, { fetchImpl });
  const verdict = await verifyEvidenceHash(ev);
  assert.strictEqual(verdict.bytesMatchHash, true);
  assert.strictEqual(verdict.attested, false);
  assert.strictEqual(verdict.serverAttestation, "off_chain_v1");
});

await test("getEvidence 404 → EvidenceNotFoundError", async () => {
  const { fetchImpl } = makeFetch({
    "/evidence": { status: 404 },
  });
  await assert.rejects(
    () => getEvidence("http://api.test", WALLET, 29, { fetchImpl }),
    EvidenceNotFoundError,
  );
});

// =============================================================================
// C — Taxonomy mirror integrity
// =============================================================================

await test("taxonomy mirror schema version matches oracle source", () => {
  // The TS mirror schema version is bumped alongside taxonomy.json.
  // A mismatch here means the mirror is stale vs the oracle.
  assert.strictEqual(TAXONOMY_SCHEMA_VERSION, 1);
});

await test("taxonomy mirror — known bits resolve", () => {
  // Every bit a label can carry must resolve to a bundled entry.
  assert.strictEqual(failureModeName(0),  "PROVISIONAL");
  assert.strictEqual(failureModeName(32), "PROMPT_INJECTION");
  assert.strictEqual(failureModeName(60), "JAILBREAK");
});

await test("taxonomy mirror — no duplicate bits", () => {
  const seen = new Set<number>();
  for (const m of FAILURE_MODES) {
    assert.strictEqual(seen.has(m.bit), false, `duplicate bit ${m.bit}`);
    seen.add(m.bit);
  }
});

await test("taxonomy mirror — failureModeByBit returns the right severity tier", () => {
  const promptInj = failureModeByBit(32);
  assert.ok(promptInj);
  assert.strictEqual(promptInj!.severity, "HIGH");
  assert.deepStrictEqual(promptInj!.owaspRefs, ["LLM01:2025"]);
});

// =============================================================================
// D — End-to-end: the "verify without trusting any vendor" demo (5 lines)
// =============================================================================

await test("5-line verify-without-trust demo", async () => {
  const wire = evidenceWire({});
  const { fetchImpl } = makeFetch({
    "/evidence": { status: 200, json: wire },
  });

  // ─── The 5 lines a consumer writes ────────────────────────────────
  const ev = await getEvidence("http://api.test", WALLET, 29, { fetchImpl });
  const ok = await verifyEvidenceHash(ev);
  if (!ok.bytesMatchHash) throw new Error("vendor tampered with bytes");
  if (!ok.attested)       throw new Error("cert v2 hash not observed yet");
  // … score now has cryptographic provenance to the on-chain cert.
  // ──────────────────────────────────────────────────────────────────

  assert.strictEqual(ok.attested, true);
});

  console.log(`\n${passed} diagnosis tests passed`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
