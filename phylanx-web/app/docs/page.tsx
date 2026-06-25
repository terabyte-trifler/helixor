import Link from "next/link";
import { ArrowUpRight, BookOpen } from "lucide-react";
import { cn } from "@/lib/cn";
import { Pill } from "@/components/ui/Pill";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Docs",
  description: "Integrate Phylanx in two lines — SDK or REST.",
};

export default function DocsPage() {
  return (
    <div className="mx-auto max-w-3xl px-6 lg:px-10 py-16 lg:py-24">
      <Pill icon={<BookOpen size={11} strokeWidth={2.5} />}>Documentation</Pill>
      <h1 className="mt-4 text-display-1 text-ink-12 tracking-tight">
        Quickstart.
      </h1>
      <p className="mt-6 text-[17px] text-ink-9 leading-relaxed max-w-[560px]">
        Phylanx exposes two read paths: an{" "}
        <Mark>on-chain SDK</Mark> for authoritative reads, and a{" "}
        <Mark>cached REST API</Mark> for high throughput. Same data, same
        canonical cert.
      </p>

      <Toc />

      <Section id="install" eyebrow="01" title="Install">
        <CodeBlock lang="bash" code={`npm install @phylanx/sdk @solana/web3.js`} />
      </Section>

      <Section id="sdk" eyebrow="02" title="Read a score on-chain">
        <p>
          The SDK reads <Code>HealthCertificate</Code> PDAs directly from
          Solana. No middleman — the chain is the source of truth.
        </p>
        <CodeBlock
          lang="ts"
          code={`import { Connection, PublicKey } from "@solana/web3.js";
import { PhylanxClient } from "@phylanx/sdk";

const connection = new Connection("https://api.mainnet-beta.solana.com");
const phylanx = new PhylanxClient({ connection });

const agentWallet = new PublicKey("Hxr1Demo01StableTrader1111111111111111111111");
const score = await phylanx.getScore(agentWallet);

console.log(score);
// {
//   score:        941,
//   alertTier:    "GREEN",
//   alertTierCode: 0,
//   epoch:        287,
//   signerCount:  3,
//   immediateRed: false,
//   computedAt:   "2026-05-22T11:00:00.000Z"
// }`}
        />
        <Callout>
          Need a specific epoch? <Code>getScoreAtEpoch(agent, epoch)</Code>.
          The full history? <Code>getScoreHistory(agent, fromEpoch, toEpoch)</Code>.
        </Callout>
      </Section>

      <Section id="api" eyebrow="03" title="Read a score via REST">
        <p>
          For higher throughput (10K req/h target, p95 under 500ms), hit
          the cached API. Same canonical cert as the SDK; no Solana RPC
          dependency on your side.
        </p>
        <CodeBlock
          lang="bash"
          code={`curl https://api.phylanx.xyz/agents/<wallet>/health

{
  "_v":              2,
  "agent_wallet":    "Hxr1Demo01StableTrader1111111111111111111111",
  "epoch":           287,
  "score":           941,
  "alert_tier":      "GREEN",
  "alert_tier_code": 0,
  "flags":           66,
  "immediate_red":   false,
  "signer_count":    3,
  "computed_at":     "2026-05-22T11:00:00.000Z"
}`}
        />
        <p>
          Other endpoints: <Code>/agents/&#123;wallet&#125;/history</Code>,{" "}
          <Code>/byzantine/recent</Code>, <Code>/byzantine/strikes</Code>,{" "}
          <Code>/challenges?node=&#123;node&#125;</Code>, <Code>/health/cluster</Code>,{" "}
          <Code>/version</Code>. Full OpenAPI schema at{" "}
          <a href="https://api.phylanx.xyz/docs" className="text-accent hover:underline">
            /docs
          </a>.
        </p>
      </Section>

      <Section id="architecture" eyebrow="04" title="What you're actually reading">
        <p>
          Every score is a <Code>HealthCertificate</Code> PDA created by
          the <Code>certificate-issuer</Code> program. The program refuses
          to write a cert unless Solana's Ed25519 precompile verifies at
          least <Mark>3 distinct signatures from registered cluster keys</Mark>{" "}
          over the canonical cert digest. No threshold, no cert.
        </p>
        <p>
          Off-chain, five oracle nodes run a commit-reveal round each
          epoch, exclude Byzantine outliers, take the median, and threshold-sign.
          A node that misbehaves 3 times is challenged on-chain and slashed.
        </p>
        <p>
          The full protocol spec lives in the repo:{" "}
          <a href="https://github.com/phylanx/phylanx" className="text-accent hover:underline inline-flex items-center gap-1">
            github.com/phylanx <ArrowUpRight size={12} />
          </a>
        </p>
      </Section>

      <Section id="schema" eyebrow="05" title="The cert, in one diagram">
        <CertDiagram />
      </Section>

      <Section id="diagnosis" eyebrow="06" title="Diagnosis: why this score, with proof">
        <p>
          A score is a number; a <Mark>diagnosis</Mark> is the why. Cert v2
          extends the on-chain attestation with five sub-scores
          (correctness, robustness, calibration, drift, coverage), the
          failure-mode bits that fired, and the remediation bits a
          well-behaved operator would address. All of it is canonical-JSON
          hashed and threshold-signed — the same trust model as the score.
        </p>

        <CodeBlock
          lang="bash"
          code={`curl https://api.phylanx.xyz/agents/<wallet>/diagnosis/287

{
  "_v":           2,
  "agent_wallet": "Hxr1Demo01StableTrader1111111111111111111111",
  "epoch":        287,
  "dimensions": {
    "correctness": 0.94, "robustness": 0.81, "calibration": 0.88,
    "drift":       0.72, "coverage":   0.79
  },
  "labels": [
    { "bit": 3,  "name": "PROMPT_INJECTION_LEAK", "fired": true },
    { "bit": 17, "name": "OUTPUT_SCHEMA_DRIFT",   "fired": true }
  ],
  "remediations": [
    { "bit": 1, "name": "TIGHTEN_SYSTEM_PROMPT" },
    { "bit": 4, "name": "ADD_OUTPUT_VALIDATOR"  }
  ],
  "attestation": { "kind": "cert_v2", "digest_hex": "8f3c…", "signers": 4 }
}`}
        />

        <p>
          The SDK decodes the wire shape into a typed object and tags each
          label with <Code>taxonomyKnown</Code> — if a server-side rename
          ever drifts from the SDK's bundled taxonomy mirror, your code
          sees it instead of silently misnaming a finding.
        </p>

        <CodeBlock
          lang="ts"
          code={`import { getDiagnosis } from "@phylanx/sdk";

const d = await getDiagnosis("https://api.phylanx.xyz", agentWallet, 287);

for (const label of d.labels.filter(l => l.fired)) {
  console.log(label.bit, label.name, label.taxonomyKnown ? "✓" : "drift");
}
// 3  PROMPT_INJECTION_LEAK ✓
// 17 OUTPUT_SCHEMA_DRIFT   ✓`}
        />

        <p>
          For the high-stakes cases (insurance underwriting, contract
          gating), the diagnosis is backed by a <Mark>threshold-attested
          evidence blob</Mark> — the raw evaluator outputs the oracle saw,
          stored on the DA layer and bound to the cert by SHA-256. The
          verify-without-trust recipe is five lines:
        </p>

        <CodeBlock
          lang="ts"
          code={`import { getEvidence, verifyEvidenceHash } from "@phylanx/sdk";

const ev   = await getEvidence("https://api.phylanx.xyz", agentWallet, 287);
const v    = await verifyEvidenceHash(ev);
if (!v.bytesMatchHash) throw new Error("evidence tampered");
// v.recomputedHashHex === v.serverAttestation.digest_hex (threshold-signed)`}
        />

        <Callout>
          <Code>verifyEvidenceHash</Code> recomputes SHA-256 over the
          evidence bytes in your process and compares to the threshold-signed
          digest. A failed check means the DA layer returned something the
          oracle quorum never signed — not a bug in the SDK, an integrity
          violation worth alerting on.
        </Callout>
      </Section>

      <div className="mt-20 pt-10 border-t border-ink-3">
        <p className="text-[14px] text-ink-9">
          Question we haven't answered?{" "}
          <a
            href="mailto:hello@phylanx.xyz"
            className="text-accent hover:underline"
          >
            hello@phylanx.xyz
          </a>
        </p>
      </div>
    </div>
  );
}

function Toc() {
  const items = [
    ["install",       "Install"],
    ["sdk",           "Read a score on-chain"],
    ["api",           "Read a score via REST"],
    ["architecture",  "What you're actually reading"],
    ["schema",        "The cert, in one diagram"],
    ["diagnosis",     "Diagnosis: why this score, with proof"],
  ];
  return (
    <nav className="mt-12 grid grid-cols-1 md:grid-cols-2 gap-y-1 gap-x-6 border-y border-ink-3 py-6">
      {items.map(([id, label], i) => (
        <a
          key={id}
          href={`#${id}`}
          className="flex items-baseline gap-3 text-[14px] text-ink-9 hover:text-ink-12 transition-colors py-1.5"
        >
          <span className="font-mono text-[11px] text-ink-7 tabular-nums">
            {String(i + 1).padStart(2, "0")}
          </span>
          {label}
        </a>
      ))}
    </nav>
  );
}

function Section({
  id, eyebrow, title, children,
}: { id: string; eyebrow: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} className="mt-20 scroll-mt-24">
      <div className="flex items-baseline gap-4">
        <span className="eyebrow-accent tabular-nums">
          {eyebrow}
        </span>
        <h2 className="text-[24px] text-ink-12 tracking-tight">{title}</h2>
      </div>
      <div className="mt-6 space-y-5 text-[15px] text-ink-9 leading-[1.75]">
        {children}
      </div>
    </section>
  );
}

function CodeBlock({ lang, code }: { lang: string; code: string }) {
  return (
    <div className="rounded-xl border border-ink-3 bg-ink-1 overflow-hidden my-6">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-ink-3">
        <span className="font-mono text-[11px] tracking-eyebrow uppercase text-ink-7">
          {lang}
        </span>
      </div>
      <pre className="px-4 py-3.5 overflow-x-auto">
        <code className="font-mono text-[13px] leading-[1.75] text-ink-11">
          {code}
        </code>
      </pre>
    </div>
  );
}

function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="font-mono text-[13px] text-ink-12 bg-ink-2 px-1.5 py-0.5 rounded border border-ink-3">
      {children}
    </code>
  );
}

function Mark({ children }: { children: React.ReactNode }) {
  return <span className="text-ink-12 font-medium">{children}</span>;
}

function Callout({ children }: { children: React.ReactNode }) {
  return (
    <div className="my-6 border-l-2 border-ink-4 pl-5 py-1 text-[14px] text-ink-9 leading-[1.7]">
      {children}
    </div>
  );
}

function CertDiagram() {
  return (
    <div className="rounded-2xl border border-ink-3 bg-ink-1 p-8 my-6">
      <pre className="font-mono text-[12px] leading-[1.6] text-ink-9 overflow-x-auto">
        {`HealthCertificate (PDA, seeds: ["cert", agent, epoch])
├── version              u8
├── agent                Pubkey   ← the scored agent
├── epoch                u64      ← which 24h window
├── score                u16      ← 0..1000
├── alert_tier           u8       ← 0 GREEN | 1 YELLOW | 2 RED
├── flags                u32      ← 32-bit detection-flag bitset
├── immediate_red        bool
├── computed_at          i64      ← unix seconds
├── digest               [u8;32]  ← sha256 of the cert payload
└── cluster_signatures   Vec<[u8;64]>
                         ↑ written by the certificate-issuer program
                           ONLY after Solana's Ed25519 precompile has
                           verified ≥ 3 distinct cluster signatures
                           over digest, otherwise the ix fails with
                           InsufficientSignatures (6033).`}
      </pre>
    </div>
  );
}
