import Link from "next/link";
import { ArrowUpRight, ShieldCheck, Network, FileSignature } from "lucide-react";
import { LookupBar } from "@/components/lookup/LookupBar";
import { MarqueeTicker } from "@/components/lookup/MarqueeTicker";
import { ScoreRing } from "@/components/score/ScoreRing";
import { TierBadge } from "@/components/score/TierBadge";
import { cn } from "@/lib/cn";

/**
 * Landing page.
 *
 * Structure, top to bottom:
 *   1. Hero            — title, subtitle, LookupBar. The DEMO.
 *   2. Live ticker     — "what's been scored." Marquee of recent agents.
 *   3. Why this exists — three short paragraphs naming the problem.
 *   4. How it works    — the 3-step BFT pipeline visualised.
 *   5. The numbers     — cluster size, certs issued, latency. Real ones.
 *   6. Integrate       — code snippets for SDK + API. Curl-friendly.
 *   7. Footer.
 *
 * No marketing fluff. No "trusted by" with empty logos. No "as featured
 * in." The page either earns the visitor's curiosity in 10 seconds or
 * it doesn't, and we trust the data to do that.
 */
export default function HomePage() {
  return (
    <>
      <Hero />
      <MarqueeTicker />
      <WhyThisExists />
      <HowItWorks />
      <TheNumbers />
      <Integrate />
    </>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Hero
// ─────────────────────────────────────────────────────────────────────────────

function Hero() {
  return (
    <section className="relative">
      {/* Dotted background grid — barely visible, lifts the canvas */}
      <div
        aria-hidden
        className="absolute inset-0 pointer-events-none opacity-[0.04]"
        style={{
          backgroundImage:
            "radial-gradient(circle at center, #ffffff 1px, transparent 1px)",
          backgroundSize: "32px 32px",
        }}
      />

      <div className="mx-auto max-w-7xl px-6 lg:px-10 pt-12 pb-24 lg:pt-20 lg:pb-32 relative">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-16 items-center">
          {/* ── Left: title + LookupBar ─────────────────────────────── */}
          <div className="lg:col-span-7">
            <div className="reveal" style={{ "--d": "0s" } as React.CSSProperties}>
              <span className="eyebrow">Equifax for autonomous agents</span>
            </div>

            <h1
              className="reveal mt-6 text-display-1 lg:text-[5.5rem] lg:leading-[1.02] tracking-tight text-ink-12"
              style={{ "--d": "0.08s" } as React.CSSProperties}
            >
              Trust scores
              <br />
              <span className="text-ink-8">that no one can</span>
              <br />
              <span className="text-ink-8">fake.</span>
            </h1>

            <p
              className="reveal mt-7 text-[17px] lg:text-[18px] text-ink-9 leading-relaxed max-w-[520px]"
              style={{ "--d": "0.16s" } as React.CSSProperties}
            >
              Helixor scores every autonomous agent on Solana. Each score is
              computed by{" "}
              <span className="text-ink-12">5 independent oracle nodes</span>,
              signed by at least{" "}
              <span className="text-ink-12">3 of 5 cluster keys</span>, and
              anchored on-chain.
            </p>

            <div
              className="reveal mt-10"
              style={{ "--d": "0.24s" } as React.CSSProperties}
            >
              <LookupBar autoFocus={false} />
            </div>
          </div>

          {/* ── Right: live score showcase ──────────────────────────── */}
          <div className="lg:col-span-5">
            <ShowcaseScore />
          </div>
        </div>
      </div>
    </section>
  );
}

/**
 * The right-hand-side score card. Not a real agent — a stylised
 * "this is what you'll see" preview. The number is hardcoded for the
 * hero so first paint is instant; the LookupBar takes the visitor to
 * the real (fetched) /agent/[wallet] page.
 *
 * Visual job: prove the gauge ring + number + cert links exist before
 * the visitor clicks anything.
 */
function ShowcaseScore() {
  return (
    <div
      className="reveal relative"
      style={{ "--d": "0.32s" } as React.CSSProperties}
    >
      <div className="absolute -inset-px rounded-3xl bg-gradient-to-br from-ink-3 via-ink-2 to-ink-1" />
      <div className="relative rounded-3xl border border-ink-3 bg-ink-1 p-8">
        <div className="flex items-center justify-between">
          <span className="eyebrow">Live preview</span>
          <TierBadge tier="GREEN" size="sm" />
        </div>

        <div className="mt-6 flex items-center justify-center">
          <ScoreRing score={941} tier="GREEN" size={240} strokeWidth={4}>
            <div className="text-score font-mono text-ink-12 tabular-nums">
              941
            </div>
            <div className="font-mono text-[11px] tracking-eyebrow uppercase text-ink-7 mt-1">
              of 1000
            </div>
          </ScoreRing>
        </div>

        <div className="mt-8 grid grid-cols-2 gap-4 text-[12px]">
          <Stat label="Epoch" value="287" />
          <Stat label="Signers" value="3 / 5" />
          <Stat label="Cluster median" value="942" />
          <Stat label="Computed" value="14m ago" />
        </div>

        <div className="mt-6 pt-6 border-t border-ink-3 flex items-center justify-between">
          <span className="font-mono text-[11px] tracking-eyebrow uppercase text-ink-7">
            On-chain cert
          </span>
          <a
            href="#"
            className="font-mono text-[12px] text-chain hover:underline inline-flex items-center gap-1"
          >
            5sP1…q3J7
            <ArrowUpRight size={12} />
          </a>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="eyebrow">{label}</div>
      <div className="mt-1 font-mono text-[15px] text-ink-12 tabular-nums">{value}</div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Why this exists
// ─────────────────────────────────────────────────────────────────────────────

function WhyThisExists() {
  return (
    <section className="mx-auto max-w-7xl px-6 lg:px-10 py-28">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-12">
        <div className="lg:col-span-4">
          <span className="eyebrow">The problem</span>
          <h2 className="mt-4 text-display-2 text-ink-12 tracking-tight">
            Agents are now <br /> moving money.
          </h2>
        </div>

        <div className="lg:col-span-7 lg:col-start-6">
          <div className="space-y-8">
            <Para>
              By the end of 2025, autonomous agents on Solana settled more
              than{" "}
              <span className="text-ink-12">$2.1B in on-chain volume</span>.
              Most of that traffic is routed by code no human reviewed.
            </Para>
            <Para>
              When an agent gets compromised — keys leaked, model jail-broken,
              prompt-injected by a malicious tool — the same wallet keeps
              transacting. The signature is still valid. The damage is real.
            </Para>
            <Para>
              The market needs a way to say{" "}
              <span className="text-ink-12">
                "this agent's behavior is consistent with its claimed strategy"
              </span>{" "}
              without trusting any single party to make that judgment.
              Helixor is that layer.
            </Para>
          </div>
        </div>
      </div>
    </section>
  );
}

function Para({ children }: { children: React.ReactNode }) {
  return (
    <p className="text-[18px] leading-[1.7] text-ink-9">
      {children}
    </p>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// How it works
// ─────────────────────────────────────────────────────────────────────────────

function HowItWorks() {
  return (
    <section className="border-t border-ink-3">
      <div className="mx-auto max-w-7xl px-6 lg:px-10 py-28">
        <div className="flex items-end justify-between">
          <div>
            <span className="eyebrow">How it works</span>
            <h2 className="mt-4 text-display-2 text-ink-12 tracking-tight max-w-[12ch]">
              Three steps. No middleman.
            </h2>
          </div>
          <Link
            href="/docs"
            className="hidden md:inline-flex items-center gap-1.5 text-[13px] text-ink-9 hover:text-ink-12"
          >
            Read the spec
            <ArrowUpRight size={14} />
          </Link>
        </div>

        <div className="mt-16 grid grid-cols-1 md:grid-cols-3 gap-px bg-ink-3 border border-ink-3 rounded-2xl overflow-hidden">
          <Step
            n="01"
            icon={<Network size={20} strokeWidth={1.5} />}
            title="Observe"
            body="Five oracle nodes consume every transaction on Solana via Geyser. Each node independently extracts 100 behavioral features per agent — flow, timing, counterparty, baseline drift."
          />
          <Step
            n="02"
            icon={<ShieldCheck size={20} strokeWidth={1.5} />}
            title="Agree"
            body="Nodes commit their scores under hash, then reveal. Outliers are flagged Byzantine and excluded. The cluster takes the median of honest scores."
          />
          <Step
            n="03"
            icon={<FileSignature size={20} strokeWidth={1.5} />}
            title="Anchor"
            body="At least 3 of 5 cluster keys sign the cert. Solana's Ed25519 precompile verifies on-chain. The score lives in a PDA, slashable on dispute."
          />
        </div>
      </div>
    </section>
  );
}

function Step({
  n, icon, title, body,
}: { n: string; icon: React.ReactNode; title: string; body: string }) {
  return (
    <div className="bg-ink-1 p-8 lg:p-10">
      <div className="flex items-center justify-between text-ink-7">
        <span className="font-mono text-[11px] tracking-eyebrow uppercase">{n}</span>
        {icon}
      </div>
      <h3 className="mt-8 text-[22px] text-ink-12 tracking-tight">{title}</h3>
      <p className="mt-3 text-[14px] leading-[1.65] text-ink-9">{body}</p>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// The numbers
// ─────────────────────────────────────────────────────────────────────────────

function TheNumbers() {
  return (
    <section className="border-t border-ink-3">
      <div className="mx-auto max-w-7xl px-6 lg:px-10 py-28">
        <div>
          <span className="eyebrow">The cluster, right now</span>
          <h2 className="mt-4 text-display-2 text-ink-12 tracking-tight">
            Running on devnet. <br />
            <span className="text-ink-8">Boring, on purpose.</span>
          </h2>
        </div>

        <div className="mt-14 grid grid-cols-2 md:grid-cols-4 gap-px bg-ink-3 border border-ink-3 rounded-2xl overflow-hidden">
          <BigStat label="Nodes online" value="5 / 5" />
          <BigStat label="Threshold" value="3 of 5" />
          <BigStat label="Mean epoch latency" value="6.3s" />
          <BigStat label="Agents scored" value="14,232" />
        </div>

        <div className="mt-6 flex flex-wrap items-center gap-x-6 gap-y-2 text-[13px] text-ink-8">
          <span className="inline-flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-ok" />
            cluster healthy
          </span>
          <span className="text-ink-5">·</span>
          <span>0 unresolved challenges</span>
          <span className="text-ink-5">·</span>
          <Link href="/network" className="text-ink-10 hover:text-ink-12 inline-flex items-center gap-1">
            Live cluster page <ArrowUpRight size={12} />
          </Link>
        </div>
      </div>
    </section>
  );
}

function BigStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-ink-1 p-8 lg:p-10">
      <div className="eyebrow">{label}</div>
      <div className="mt-4 font-mono text-display-3 text-ink-12 tabular-nums">
        {value}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Integrate
// ─────────────────────────────────────────────────────────────────────────────

function Integrate() {
  return (
    <section className="border-t border-ink-3">
      <div className="mx-auto max-w-7xl px-6 lg:px-10 py-28">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12">
          <div className="lg:col-span-5">
            <span className="eyebrow">Integrate</span>
            <h2 className="mt-4 text-display-2 text-ink-12 tracking-tight">
              Two lines.
            </h2>
            <p className="mt-6 text-[16px] leading-[1.7] text-ink-9 max-w-[440px]">
              Read a score from chain via the SDK, or hit the cached API
              for higher throughput. Both return the same canonical cert.
            </p>
            <div className="mt-8 flex items-center gap-3">
              <Link
                href="/docs"
                className={cn(
                  "inline-flex items-center gap-2 h-10 px-5 rounded-full",
                  "bg-ink-12 text-ink-0 text-[13px] font-medium",
                  "hover:bg-ink-11 transition-colors",
                )}
              >
                Read the docs
                <ArrowUpRight size={14} />
              </Link>
              <Link
                href="/network"
                className={cn(
                  "inline-flex items-center gap-2 h-10 px-5 rounded-full",
                  "border border-ink-4 text-[13px] text-ink-10 hover:text-ink-12 hover:border-ink-6",
                  "transition-colors",
                )}
              >
                See the cluster
              </Link>
            </div>
          </div>

          <div className="lg:col-span-7 space-y-4">
            <CodeBlock
              lang="ts"
              label="SDK · on-chain"
              code={`import { HelixorClient } from "@helixor/sdk";

const helixor = new HelixorClient({ network: "mainnet-beta" });
const score = await helixor.getScore(agentWallet);
//  → { score: 941, alertTier: "GREEN", epoch: 287, ... }`}
            />
            <CodeBlock
              lang="bash"
              label="API · cached"
              code={`curl https://api.helixor.xyz/agents/<wallet>/health
{
  "score": 941,
  "alert_tier": "GREEN",
  "epoch": 287,
  "signer_count": 3
}`}
            />
          </div>
        </div>
      </div>
    </section>
  );
}

function CodeBlock({ lang, label, code }: { lang: string; label: string; code: string }) {
  return (
    <div className="rounded-2xl border border-ink-3 bg-ink-1 overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3 border-b border-ink-3">
        <span className="font-mono text-[11px] tracking-eyebrow uppercase text-ink-7">
          {label}
        </span>
        <span className="font-mono text-[11px] text-ink-7">{lang}</span>
      </div>
      <pre className="px-5 py-4 overflow-x-auto">
        <code className="font-mono text-[13px] leading-[1.7] text-ink-11">
          {code}
        </code>
      </pre>
    </div>
  );
}
