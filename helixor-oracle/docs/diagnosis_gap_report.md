# Helixor Diagnosis — Gap Report (Day 33, frozen)

This document is the **permanent ground-truth table** for the
"score → diagnosis" pivot. Every future planning session should read
this file first instead of re-deriving the answer from a fresh
codebase sweep; the §3 column ("Plan-against") is the canonical record
of what's already wired versus what's still on the to-do list.

The information here was verified directly against the codebase at
the time of the Day-33 commit. The point of writing it down is that
future re-research (by humans or agents) has tended to re-discover
AW-04 + ScoreComponentsAccount as if they were missing — they have
been on-chain since Day 19 and the gap is *exposure*, not *capture*.

---

## §0 — Verified ground-truth surface

### What we already have on-chain

| Surface | Where | Capacity for diagnosis |
|---|---|---|
| `HealthCertificate.score`            | `programs/certificate-issuer/src/state/health_certificate.rs` | 0–1000 u16. Score only. |
| `HealthCertificate.alert_tier`       | same | GREEN / YELLOW / RED (u8). |
| `HealthCertificate.flags`            | same | u32 — already a **failure-mode bitmask** (FlagBit). |
| `HealthCertificate.immediate_red`    | same | fast-path Boolean. |
| `ScoreComponentsAccount`             | `programs/certificate-issuer/src/state/score_components.rs` | **AW-04 payload PDA, per-(agent, epoch). Carries the full canonical JSON breakdown** (dims, confidence, gaming, agg_flags) — hash-bound to the cert via the AW-04 digest. |
| `BaselineDataAccount`                | `programs/certificate-issuer/src/state/baseline_data.rs` | AW-03 payload PDA, the full canonical baseline bytes. |
| `scoring_code_hash`                  | cert + AW-04 fold | SHA-256 over the scoring kernel source + algo/weights version. |
| `input_commitment`                   | cert | AW-01 — cluster-majority SHA-256 over input transactions. |
| `slot_anchor (slot, hash)`           | cert | AW-01-EXT — Solana slot + block hash, sysvar-verified. |

### What the API / web app expose today

| Endpoint / view | What it returns | Diagnosis depth |
|---|---|---|
| `GET /agents/{wallet}/health/{epoch}` (`helixor-api/api/schemas.py::HealthResponse`) | `score`, `alert_tier`, `flag_set_token` (VULN-24 opaque hash), `flag_count` (popcount only) | **score-only** |
| `app/agent/[wallet]/page.tsx`        | score ring + tier badge + flag count | **score-only** |

The cert carries everything needed to render a diagnostic surface
**today**; the API and the web app simply do not read past `score`
and `flag_count`.

### What's in helixor-oracle (off-chain)

| Module | Capacity |
|---|---|
| `detection/types.py::FlagBit`        | Frozen u32 universal + per-dimension flag layout. **This is the taxonomy seed.** |
| `oracle/score_components.py`         | AW-04 canonical-JSON serializer. Already produces the per-dimension breakdown we need. |
| `scoring/`                           | Dimension-specific detectors. Each returns a `DimensionResult` with `flags: int` already. |

---

## §1 — Day-33 deliverable (this commit)

### New package — `diagnosis/`

| File | Role |
|---|---|
| `diagnosis/taxonomy.py`        | `FailureMode(enum.IntFlag)` u64. Low 32 bits **mirror** `detection.types.FlagBit` (import-time assert). High 32 bits carry the OWASP-aligned + practitioner labels. |
| `diagnosis/remediation.py`     | `RemediationCode(enum.IntFlag)` u32. Containment / hardening / recovery / escalation groups. |
| `diagnosis/decode.py`          | `decode(mask) -> tuple[DecodedLabel, ...]`, `default_remediation(mask)`, `severity_of(mask)`. |
| `diagnosis/__main__.py`        | `python3 -m diagnosis [--in-place]` emits `taxonomy.json`. |
| `diagnosis/taxonomy.json`      | **Generated.** Single source of truth web app imports on Day 35. |
| `tests/diagnosis/test_taxonomy_v1.py` | ~50 pin tests (~126 after pytest parametrize expansion). |

### Frozen v1 surface

- **40 FailureMode bits** — 9 legacy passthroughs + 31 new diagnosis labels.
- **24 RemediationCode bits.**
- **Bit 63 is reserved**; new diagnosis labels grow from bit 53 upward only (after the OWASP block is full, room remains in the 22–28 legacy gap for future per-dimension bits).
- Legacy passthrough invariant: `failure_mode_bitmask & 0xFFFF_FFFF == FlagBit-shaped u32` for every legacy bit. Any downstream code that still reads the old `flags: u32` decodes the low half of the new field unchanged.

---

## §2 — OWASP alignment table

The high 32 bits map 1:1 to the canonical OWASP corpus where one
exists. Multiple-entry refs (e.g. `SUPPLY_CHAIN_COMPROMISE`) trace
to the *intersection* of an LLM-Top-10 entry and an Agentic-Top-10
entry; the bit's semantic is that intersection, not either alone.

| FailureMode bit | OWASP ref(s) |
|---|---|
| `PROMPT_INJECTION`            | LLM01:2025 |
| `SENSITIVE_INFO_DISCLOSURE`   | LLM02:2025 |
| `SUPPLY_CHAIN_COMPROMISE`     | LLM03:2025, ASI04:2026 |
| `DATA_MODEL_POISONING`        | LLM04:2025 |
| `IMPROPER_OUTPUT_HANDLING`    | LLM05:2025 |
| `EXCESSIVE_AGENCY`            | LLM06:2025 |
| `SYSTEM_PROMPT_LEAK`          | LLM07:2025 |
| `VECTOR_EMBEDDING_WEAKNESS`   | LLM08:2025 |
| `MISINFORMATION`              | LLM09:2025 |
| `UNBOUNDED_CONSUMPTION`       | LLM10:2025 |
| `AGENT_GOAL_HIJACK`           | ASI01:2026 |
| `TOOL_MISUSE`, `TOOL_LOOP`    | ASI02:2026 |
| `IDENTITY_PRIVILEGE_ABUSE`    | ASI03:2026 |
| `UNEXPECTED_CODE_EXECUTION`   | ASI05:2026 |
| `MEMORY_POISONING`, `CONTEXT_POISONING` | ASI06:2026 |
| `INSECURE_INTER_AGENT_COMM`   | ASI07:2026 |
| `CASCADING_AGENT_FAILURE`     | ASI08:2026 |
| `HUMAN_TRUST_EXPLOITATION`    | ASI09:2026 |
| `ROGUE_AGENT`                 | ASI10:2026 |

Practitioner-only labels (no OWASP ref): `HALLUCINATION_CASCADE`,
`OUTPUT_DISTRIBUTION_DRIFT`, `CONTEXT_WINDOW_EXHAUSTION`,
`LATENCY_DEGRADATION`, `COST_BLOWUP`, `ALIGNMENT_REGRESSION`,
`DATA_LEAKAGE`, `JAILBREAK`, `SUB_AGENT_DEADLOCK`, `ROLE_CONFUSION`.

---

## §3 — Plan-against: what's done vs. what's still open

| Capability | Status | Notes |
|---|---|---|
| Diagnostic taxonomy (frozen bit layout) | **DONE — Day 33** | `diagnosis/taxonomy.py`. |
| RemediationCode bitmask                 | **DONE — Day 33** | `diagnosis/remediation.py`. |
| Label↔remediation default mapping       | **DONE — Day 33** | `LABEL_METADATA[*].default_remediation`. |
| `taxonomy.json` export                  | **DONE — Day 33** | `python3 -m diagnosis --in-place`. |
| Per-dimension breakdown payload         | **Already on-chain** | `ScoreComponentsAccount` (AW-04). |
| Baseline DA payload                     | **Already on-chain** | `BaselineDataAccount` (AW-03). |
| Scoring-kernel provenance               | **Already on-chain** | `scoring_code_hash`. |
| Input commitment + slot anchor          | **Already on-chain** | AW-01, AW-01-EXT. |
| API endpoint `GET …/diagnosis/{epoch}`  | **Open — Day 34** | New `DiagnosisResponse` schema in `helixor-api/api/schemas.py`. |
| Web app diagnostic panel                | **Open — Day 35** | Consume `taxonomy.json` from this commit; render decoded labels + remediations. |
| Cert v2 (`failure_mode_bitmask: u64`)   | **Open — Phase 2** | Anchor program change. Low 32 bits = current `flags`. High 32 bits = new diagnosis labels. |
| Cert v2 (`remediation_codes: u32`)      | **Open — Phase 2** | Same. |
| Cert v2 (`diagnosis_payload_hash`)      | **Open — Phase 2** | DA payload analogous to AW-03 baseline DA. |
| Per-label scorers (oracle node)         | **Open — Phase 3** | Each FailureMode bit needs a deterministic detector to drive consensus. |

**Key non-obvious property:** the on-chain primitives needed to make
diagnosis non-repudiable already exist (AW-01, AW-01-EXT, AW-03,
AW-04, scoring_code_hash, threshold attestation). The Phase-2
certificate-schema bump is widening the field surface; it is **not**
adding new attestation surface. Threshold signing remains identical.

---

## §4 — Why this layout is frozen

A bit-position change to `FailureMode` is an interpretation drift
that downstream consumers cannot catch at code review: every existing
cert continues to decode under the new layout and silently mis-labels.

The defences against silent drift, in order of how-hard-to-defeat:

1. **Module-import-time invariants** in `taxonomy.py`
   (`_verify_taxonomy_invariants`). The package refuses to import
   if any one of {single-bit, unique, fits-u64, FlagBit mirror by
   name *and* value, metadata complete, no orphan entries, bit 63
   unset} is broken.
2. **Pin tests** in `tests/diagnosis/test_taxonomy_v1.py` — every
   name → exact bit, parametrized for fast review.
3. **JSON export round-trip tests** — `taxonomy.json` and the
   in-memory metadata must agree.
4. **Trace-tier-unset invariant**: every FailureMode bit must have a
   declared `Severity`. A label without a tier is unshippable.

If you are about to bump a bit position because "we only had one
testnet deploy", **stop**. Even one consumer that cached a label
against `bit=42` will mis-label for the rest of time after the bump.
The cheapest fix is always to claim a new bit; bits 21-28 and 30-31
in the legacy half plus bit 63 in the new half are reservable
slots.
