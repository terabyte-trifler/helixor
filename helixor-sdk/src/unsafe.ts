// =============================================================================
// helixor-sdk/src/unsafe.ts — RAW cert-reading primitives.
//
// DBP-3: this entry point exposes the surfaces that read a Helixor cert
// WITHOUT any safety guards. A consumer importing from here is committing
// to wire VULN-23 (`SafeCertReader`), SOL-3 (per-operation freshness
// floors), AW-01 (`verifyInputProvenance`) and AW-01-EXT
// (`verifyAgainstSolanaLedger`) THEMSELVES.
//
// THE CONTRACT
// ------------
// The default `@helixor/sdk` entry point exports ONLY structurally-safe
// surfaces: `SafeCertReader`, the verify-* functions, decoders, PDA
// helpers, and DBP-2 `VerifiedConsumer` helpers. Raw cert-reading is
// behind THIS subpath specifically so a consumer cannot "accidentally"
// get a raw score — they have to type the word `unsafe` to instantiate
// `HelixorChainClient` or `HelixorClient`.
//
// THE DBP-1 LINTER ENFORCES THIS
// -------------------------------
// `audit/consumer_integration_check.py` (DBP-1e) HARD-fails any
// Verified-Integrator cert-reader source that imports from
// `@helixor/sdk/unsafe` UNLESS the same file ALSO uses
// `SafeCertReader`. The intended pattern is:
//
//     // ALLOWED — raw client is wrapped in SafeCertReader.
//     import { HelixorChainClient } from "@helixor/sdk/unsafe";
//     import { SafeCertReader }     from "@helixor/sdk";
//     const safe = new SafeCertReader({
//       chainReader: new HelixorChainClient(connection, programs),
//     });
//
// versus:
//
//     // REJECTED — raw chain client used without a safety wrap.
//     import { HelixorChainClient } from "@helixor/sdk/unsafe";
//     const score = await new HelixorChainClient(conn, ids).getScore(agent);
//
// WHY NOT JUST DELETE THE RAW PRIMITIVES?
// ---------------------------------------
// Some consumers legitimately need them: indexers, validators, the
// integration / e2e test suites, internal tooling. Deletion would force
// those to maintain a fork. Hiding them behind a `/unsafe` subpath that
// the linter recognises is the audit-acceptable compromise: misuse
// becomes opt-in, not opt-out, and the lint flags it before it ships.
// =============================================================================

export {
  HelixorClient,
  HelixorError,
  AgentNotFoundError,
  type TrustScore,
  type RequireMinScoreOptions,
} from "./http_client";

export {
  HelixorChainClient,
  CertificateNotFoundError,
} from "./client";
