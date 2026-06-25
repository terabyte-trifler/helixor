import Link from "next/link";
import {
  Activity, ArrowRight, ArrowUpRight, Check, HelpCircle, Settings, X,
} from "lucide-react";
import { LookupBar } from "@/components/lookup/LookupBar";
import { Terminal } from "@/components/landing/Terminal";
import { ApproachSteps } from "@/components/landing/ApproachSteps";
import { ConvergenceBridge } from "@/components/landing/ConvergenceBridge";
import { Hero } from "@/components/landing/Hero";
import { AgentShowcase } from "@/components/landing/AgentShowcase";
import { Reveal } from "@/components/motion/Reveal";
import { CountUp } from "@/components/motion/CountUp";
import { Scramble } from "@/components/motion/Scramble";
import { cn } from "@/lib/cn";
import { Pill } from "@/components/ui/Pill";

/**
 * Landing page — v3 "vermilion" rebuild.
 *
 *   1. Hero          — solid accent block, black display type, LookupBar,
 *                      marquee strip on the block's bottom edge.
 *   2. The problem   — centered pill, highlighted-word headline, node-radar
 *                      illustration (ours: the Byzantine story) + 2×2 villains.
 *   3. The answer    — centered pill + intro.
 *   4. Our approach  — Steps 01-03 selector with swapping data cards.
 *   5. Stat strip    — four measured numbers.
 *   6. Engineered    — terminal centerpiece with radiating callouts.
 *   7. Trust math    — comparison rows; green marks the good number.
 *   8. FAQ           — native details, honest answers.
 *   9. Finale        — original wireframe grid + notched CTA.
 *
 * Every sentence original. Every number measured on this build.
 */
export default function HomePage() {
  return (
    <>
      <Hero />
      <ConvergenceBridge />
      <Problem />
      <Approach />
      <StatStrip />
      <Showcase />
      <Engineered />
      <TrustMath />
      <Faq />
      <Finale />
    </>
  );
}

/* Pill is shared app-wide from components/ui/Pill. */

function SectionHead({
  icon, pill, title, sub,
}: { icon: React.ReactNode; pill: string; title: React.ReactNode; sub?: string }) {
  return (
    <Reveal className="flex flex-col items-center text-center">
      <Pill icon={icon}><Scramble text={pill} /></Pill>
      <h2 className="mt-6 text-display-2 text-ink-12 max-w-[22ch]">{title}</h2>
      {sub && (
        <p className="mt-5 text-[15px] leading-[1.7] text-ink-9 max-w-[52ch]">{sub}</p>
      )}
    </Reveal>
  );
}

/* ── 2 · The problem ────────────────────────────────────────────────────── */

const VILLAINS = [
  {
    id: "001",
    tag: "Compromised keys",
    title: "Stolen keys keep signing.",
    body: "When an agent is compromised — keys leaked, model hijacked, tool poisoned — its wallet keeps transacting. Every signature is still valid. Validity is not trustworthiness.",
  },
  {
    id: "002",
    tag: "Trust by vibes",
    title: "Allowlists run on rumor.",
    body: "Integrators vouch for agents based on a Twitter thread, a README, and hope. There is no shared, checkable record of how an agent actually behaves.",
  },
  {
    id: "003",
    tag: "Coercible scorers",
    title: "One scorer is one target.",
    body: "A centralized reputation service can be paid, pressured, or compelled into a verdict — and you would never know. Whoever owns the database owns the truth.",
  },
  {
    id: "004",
    tag: "Walled gardens",
    title: "Reputation dies at the border.",
    body: "An agent's track record on one platform is invisible to every other. Eighteen months of good behavior resets to zero with every new integration.",
  },
];

function Problem() {
  return (
    <section className="mx-auto max-w-7xl px-6 lg:px-10 py-24 lg:py-28">
      <Reveal>
        <div className="flex justify-center">
          <Pill icon={<X size={11} strokeWidth={2.5} />}><Scramble text="The problem" /></Pill>
        </div>
        <h2 className="mt-8 text-display-2 lg:text-[3.5rem] text-ink-12 max-w-[20ch]">
          Agents move money.
          <br />
          Nobody{" "}
          <span className="bg-accent text-ink-0 px-2 -mx-1">vouches</span>{" "}
          for them.
        </h2>
      </Reveal>

      <div className="mt-14 grid grid-cols-1 lg:grid-cols-3 gap-px bg-ink-3 border border-ink-3">
        {/* Illustration cell — ours: 5-node radar, one flagged */}
        <div className="bg-ink-1 p-8 flex items-center justify-center lg:row-span-2">
          <NodeRadar />
        </div>
        {VILLAINS.map((v) => (
          <div key={v.id} className="bg-ink-1 p-8">
            <div className="flex items-center justify-between">
              <span className="font-mono text-[11px] tracking-eyebrow uppercase text-accent">
                {v.tag}
              </span>
              <span className="font-mono text-[11px] text-ink-6 tabular-nums">{v.id}</span>
            </div>
            <h3 className="mt-5 text-[21px] text-ink-12">{v.title}</h3>
            <p className="mt-3 text-[13.5px] leading-[1.7] text-ink-9">{v.body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

/** Original illustration: the cluster as a radar — five nodes, one caught. */
function NodeRadar() {
  // Pentagon positions around center (200,200), r=120.
  const nodes = [
    { x: 200, y: 80,  bad: false },
    { x: 314, y: 163, bad: false },
    { x: 271, y: 297, bad: true  },   // node-2 — the liar
    { x: 129, y: 297, bad: false },
    { x: 86,  y: 163, bad: false },
  ];
  return (
    <svg
      viewBox="0 0 400 400"
      className="w-full max-w-[320px]"
      role="img"
      aria-label="Five oracle nodes arranged in a ring; one node deviates and is flagged"
    >
      {/* concentric rings */}
      {[60, 100, 140, 175].map((r) => (
        <circle key={r} cx="200" cy="200" r={r} fill="none" stroke="#2c2624" strokeWidth="1" />
      ))}
      {/* the sweep — cluster watch, watching */}
      <g className="radar-sweep">
        <line x1="200" y1="200" x2="200" y2="28" stroke="#ff4f2e" strokeWidth="1.25" opacity="0.7" />
        <circle cx="200" cy="34" r="2.5" fill="#ff4f2e" opacity="0.9" />
      </g>
      {/* crosshair */}
      <line x1="200" y1="12" x2="200" y2="388" stroke="#221d1b" strokeWidth="1" />
      <line x1="12" y1="200" x2="388" y2="200" stroke="#221d1b" strokeWidth="1" />
      {/* corner brackets */}
      {[
        "M24 56 V24 H56", "M344 24 H376 V56",
        "M376 344 V376 H344", "M56 376 H24 V344",
      ].map((d) => (
        <path key={d} d={d} fill="none" stroke="#524a47" strokeWidth="2" />
      ))}
      {/* consensus links between honest nodes — the mesh breathes */}
      <g className="radar-mesh">
        {nodes.filter((n) => !n.bad).map((a, i, arr) =>
          arr.slice(i + 1).map((b) => (
            <line
              key={`${a.x}-${b.x}`}
              x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke="#383130" strokeWidth="1"
            />
          )),
        )}
      </g>
      {/* nodes */}
      {nodes.map((n, i) => (
        <g key={i}>
          {n.bad && (
            <circle
              className="radar-flag-ring"
              cx={n.x} cy={n.y} r="16" fill="none"
              stroke="#ff4f2e" strokeWidth="1.5" strokeDasharray="3 3"
            />
          )}
          <circle
            className={n.bad ? undefined : "radar-node"}
            style={n.bad ? undefined : { animationDelay: `${i * 0.45}s` }}
            cx={n.x} cy={n.y} r="6" fill={n.bad ? "#ff4f2e" : "#e8e1d8"}
          />
        </g>
      ))}
      {/* flag label */}
      <text className="radar-flag-label" x="271" y="336" textAnchor="middle" fill="#ff4f2e"
        fontFamily="var(--font-mono)" fontSize="11" letterSpacing="1.5">
        NODE-2 · FLAGGED
      </text>
      <text x="200" y="32" textAnchor="middle" fill="#6b625e"
        fontFamily="var(--font-mono)" fontSize="10" letterSpacing="2">
        CLUSTER WATCH
      </text>
    </svg>
  );
}

/* ── 3+4 · Our approach ─────────────────────────────────────────────────── */

function Approach() {
  return (
    <section className="border-t border-ink-3">
      <div className="mx-auto max-w-7xl px-6 lg:px-10 py-24 lg:py-28">
        <SectionHead
          icon={<Settings size={11} strokeWidth={2.5} />}
          pill="Our approach"
          title="Consensus beats trust."
          sub="Phylanx is a closed loop — detection, consensus, signatures, and storage — engineered together for one job: a score nobody has to take on faith."
        />
        <div className="mt-16">
          <ApproachSteps />
        </div>
      </div>
    </section>
  );
}

/* ── 5 · Stat strip ─────────────────────────────────────────────────────── */

const STATS = [
  { label: "Latency",   value: "3.2ms",  note: "cached read · p95" },
  { label: "Threshold", value: "3 of 5", note: "signatures per cert" },
  { label: "Consensus", value: "6.3s",   note: "mean per epoch" },
  { label: "Cost",      value: "$0",     note: "permissionless reads" },
];

function StatStrip() {
  return (
    <section className="border-t border-ink-3">
      <div className="mx-auto max-w-7xl px-6 lg:px-10">
        <div className="grid grid-cols-2 lg:grid-cols-4 divide-x divide-ink-3 border-x border-ink-3">
          {STATS.map((s, i) => (
            <Reveal key={s.label} delay={i * 90} className="p-7 lg:p-9">
              <div className="font-mono text-[11px] tracking-eyebrow uppercase text-accent">
                {s.label}
              </div>
              <div className="mt-3 text-display-3 lg:text-[2.5rem] text-ink-12 tabular-nums">
                <CountUp value={s.value} />
              </div>
              <div className="mt-2 font-mono text-[11.5px] text-ink-7">{s.note}</div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── 5.5 · Showcase — the four demo agents, tabbed ──────────────────────── */

function Showcase() {
  return (
    <section className="border-t border-ink-3">
      <div className="mx-auto max-w-7xl px-6 lg:px-10 py-24 lg:py-28">
        <SectionHead
          icon={<Activity size={11} strokeWidth={2.5} />}
          pill="Live demo"
          title="Four agents. Four verdicts."
          sub="The same certificate format, telling four different truths. Click through — or follow any card to its full on-chain record."
        />
        <div className="mt-14 max-w-5xl mx-auto">
          <AgentShowcase />
        </div>
      </div>
    </section>
  );
}

/* ── 6 · Engineered — terminal centerpiece with callouts ────────────────── */

const CALLOUTS_LEFT = [
  { t: "Commit-reveal", c: "nobody copies anybody" },
  { t: "BFT threshold", c: "3 of 5 keys must sign" },
  { t: "Ed25519",       c: "verified on-chain" },
];
const CALLOUTS_RIGHT = [
  { t: "Byzantine watchdog", c: "outliers struck" },
  { t: "On-chain slashing",  c: "lying costs stake" },
  { t: "Two read paths",     c: "SDK + cached API" },
];

function Engineered() {
  return (
    <section className="border-t border-ink-3">
      <div className="mx-auto max-w-7xl px-6 lg:px-10 py-24 lg:py-28">
        <SectionHead
          icon={<Activity size={11} strokeWidth={2.5} />}
          pill="Engineered consensus"
          title="Built for the trustless."
        />

        <div className="mt-16 grid grid-cols-1 lg:grid-cols-12 gap-10 items-center">
          <div className="hidden lg:flex lg:col-span-3 flex-col gap-12 items-end text-right">
            {CALLOUTS_LEFT.map((c) => (
              <Callout key={c.t} t={c.t} c={c.c} align="right" />
            ))}
          </div>
          <div className="lg:col-span-6">
            <Terminal />
          </div>
          <div className="hidden lg:flex lg:col-span-3 flex-col gap-12">
            {CALLOUTS_RIGHT.map((c) => (
              <Callout key={c.t} t={c.t} c={c.c} align="left" />
            ))}
          </div>
          {/* Mobile: callouts as a compact grid below the terminal */}
          <div className="lg:hidden grid grid-cols-2 gap-6">
            {[...CALLOUTS_LEFT, ...CALLOUTS_RIGHT].map((c) => (
              <Callout key={c.t} t={c.t} c={c.c} align="left" />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function Callout({ t, c, align }: { t: string; c: string; align: "left" | "right" }) {
  return (
    <div className={cn("max-w-[180px]", align === "right" ? "text-right" : "text-left")}>
      <div className="font-mono text-[11px] tracking-eyebrow uppercase text-ink-11">{t}</div>
      <div className="mt-1.5 font-mono text-[11px] tracking-wide uppercase text-ink-7 leading-[1.6]">
        {c}
      </div>
      <div className={cn("mt-3 h-px w-10 bg-accent/50", align === "right" ? "ml-auto" : "")} aria-hidden />
    </div>
  );
}

/* ── 7 · Trust math ─────────────────────────────────────────────────────── */

function GoodBar({ filled, total }: { filled: number; total: number }) {
  return (
    <span className="font-mono text-data-green" aria-hidden>
      {"▰".repeat(filled)}
      <span className="text-ink-4">{"▱".repeat(total - filled)}</span>
    </span>
  );
}

function TrustMath() {
  return (
    <section className="border-t border-ink-3">
      <div className="mx-auto max-w-7xl px-6 lg:px-10 py-24 lg:py-28">
        <SectionHead
          icon={<Check size={11} strokeWidth={2.5} />}
          pill="Trust math"
          title="Count the parties you have to trust."
        />

        <Reveal delay={120} className="mt-14 grid grid-cols-1 lg:grid-cols-2 gap-px bg-ink-3 border border-ink-3">
          <div className="bg-ink-1 p-8 lg:p-10 space-y-8">
            <CompareRow
              label="Parties that must collude to fake a verdict"
              rows={[
                { name: "centralized scorer", value: "1", bar: <span className="font-mono text-ink-6">▰<span className="text-ink-4">▱▱▱▱▱▱▱▱▱</span></span> },
                { name: "phylanx", value: "3 of 5 — each staked, each slashable", bar: <GoodBar filled={3} total={10} />, good: true },
              ]}
            />
            <CompareRow
              label="How you verify a score"
              rows={[
                { name: "centralized scorer", value: "trust the dashboard" },
                { name: "phylanx", value: "recompute the digest, check 3 signatures", good: true },
              ]}
            />
          </div>
          <div className="bg-ink-1 p-8 lg:p-10 space-y-8">
            <CompareRow
              label="What happens to a lying scorer"
              rows={[
                { name: "centralized scorer", value: "nothing — you can't even see it" },
                { name: "phylanx", value: "flagged on-chain · struck · stake slashed", good: true },
              ]}
            />
            <CompareRow
              label="Cost to read a score"
              rows={[
                { name: "centralized scorer", value: "a seat license and an account manager" },
                { name: "phylanx", value: "$0 — permissionless, on-chain or cached", good: true },
              ]}
            />
          </div>
        </Reveal>

        <p className="mt-6 text-center font-mono text-[12px] text-ink-7">
          measured on this build: epoch consensus 6.3s mean · cached read p95 3.2ms · 1,000-cert chaos run 2:12
        </p>
      </div>
    </section>
  );
}

function CompareRow({
  label, rows,
}: {
  label: string;
  rows: { name: string; bar?: React.ReactNode; value: string; good?: boolean }[];
}) {
  return (
    <div>
      <div className="font-mono text-[11px] tracking-eyebrow uppercase text-accent">{label}</div>
      <div className="mt-4 space-y-3">
        {rows.map((r) => (
          <div key={r.name} className="grid grid-cols-12 gap-3 items-baseline">
            <span className="col-span-4 font-mono text-[12px] text-ink-8">{r.name}</span>
            <span className="col-span-8 font-mono text-[13px]">
              {r.bar ? <>{r.bar}{" "}</> : null}
              <span className={r.good ? "text-data-green" : "text-ink-9"}>{r.value}</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── 8 · FAQ ────────────────────────────────────────────────────────────── */

const FAQ = [
  {
    q: "What is Phylanx?",
    a: "A permissionless trust layer for autonomous agents on Solana. Five independent oracle nodes score every agent's on-chain behavior each epoch; at least three must sign before a certificate is written. Anyone can read a score; no one — including us — can forge or edit one.",
  },
  {
    q: "How is a score computed?",
    a: "Each node extracts one hundred behavioral features across five dimensions — flow, timing, counterparties, drift, and security — against a baseline the agent committed on-chain. The composite lands between 0 and 1000, with GREEN, YELLOW, and RED alert tiers at 800 and 400.",
  },
  {
    q: "Can a single node fake a score?",
    a: "No. A certificate requires at least 3 of 5 distinct cluster signatures over its digest, verified by Solana's Ed25519 precompile inside the issuing program. One node — or two — simply cannot produce a valid certificate.",
  },
  {
    q: "What happens when a node lies?",
    a: "Its reveal deviates from the cluster median, the watchdog flags it, and it is excluded from that epoch's signing set. Repeated deviation opens a permissionless on-chain challenge with the conflicting scores as evidence, and the node's stake is slashed.",
  },
  {
    q: "Is this live right now?",
    a: "The cluster runs on devnet and the full pipeline — detection, consensus, threshold signing, certificates — is built and tested (1,300+ tests). This site shows illustrative data shaped exactly like the live API until the public deployment lands; the banner at the top disappears the day it does.",
  },
  {
    q: "How do I integrate?",
    a: "Two lines. Read authoritative scores on-chain with the TypeScript SDK, or hit the cached REST API for high-throughput reads at 3.2ms p95. Both return the same canonical certificate — start with the quickstart in the docs.",
  },
];

function Faq() {
  return (
    <section className="border-t border-ink-3">
      <div className="mx-auto max-w-3xl px-6 lg:px-10 py-24 lg:py-28">
        <div className="flex justify-center">
          <Pill icon={<HelpCircle size={11} strokeWidth={2.5} />}>FAQ</Pill>
        </div>
        <h2 className="mt-6 text-display-2 text-ink-12 text-center">Fair questions.</h2>
        <div className="mt-12 border-t border-ink-3">
          {FAQ.map((item, i) => (
            <details key={item.q} className="faq border-b border-ink-3">
              <summary className="flex items-baseline gap-5 py-6 group">
                <span className="font-mono text-[11px] text-accent tabular-nums shrink-0">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <span className="flex-1 text-[16px] text-ink-11 group-hover:text-ink-12 transition-colors">
                  {item.q}
                </span>
                <span className="faq-toggle font-mono text-[16px] text-ink-7 select-none" aria-hidden>
                  +
                </span>
              </summary>
              <p className="pb-7 pl-[42px] pr-8 text-[14.5px] leading-[1.75] text-ink-9">
                {item.a}
              </p>
            </details>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── 9 · Finale — original wireframe grid + notched CTA ─────────────────── */

function Finale() {
  return (
    <section className="relative border-t border-ink-3 overflow-hidden">
      <WireGrid />
      <Reveal className="relative mx-auto max-w-7xl px-6 lg:px-10 py-28 lg:py-40 text-center">
        <div className="font-mono text-accent text-[28px] tracking-[-0.06em] select-none" aria-hidden>
          ///
        </div>
        <h2 className="mt-6 text-display-1 lg:text-[4.75rem] text-ink-12">
          Don't trust. Verify.
        </h2>
        <div className="mt-10 flex items-center justify-center">
          <Link
            href="/agent/Hxr4Demo04FlaggedExfilAgent1111111111111111x"
            className={cn(
              "btn-notch group inline-flex items-center gap-3 h-14 px-10",
              "bg-accent text-ink-0 font-mono text-[14px] font-medium tracking-wide",
              "hover:bg-accent-bright transition-colors",
            )}
          >
            Score an agent
            <ArrowRight size={16} strokeWidth={2.25} className="transition-transform duration-300 group-hover:translate-x-1.5" />
          </Link>
        </div>
        <p className="mt-6 font-mono text-[12px] text-ink-7">
          No account. No key. The chain is the login.
        </p>
        <div className="mt-10">
          <Link
            href="/docs"
            className="inline-flex items-center gap-1.5 text-[13px] text-ink-9 hover:text-ink-12 transition-colors"
          >
            or read the docs <ArrowUpRight size={13} />
          </Link>
        </div>
      </Reveal>
    </section>
  );
}

/** Original perspective wireframe — concentric arcs + radial spokes,
 *  vermilion strokes fading toward the horizon. Pure SVG, ours. */
function WireGrid() {
  const spokes = Array.from({ length: 15 }, (_, i) => {
    const x = (i / 14) * 1600;
    return <line key={i} x1="800" y1="-80" x2={x} y2="900" stroke="#ff4f2e" strokeWidth="1" />;
  });
  const arcs = [120, 200, 300, 420, 560, 720, 900].map((r, i) => (
    <ellipse
      key={r}
      className="wire-arc"
      style={{ animationDelay: `${i * 0.7}s` }}
      cx="800" cy="900" rx={r * 1.9} ry={r * 0.62}
      fill="none" stroke="#ff4f2e" strokeWidth="1"
      opacity={0.25 + i * 0.1}
    />
  ));
  return (
    <div className="absolute inset-0 pointer-events-none" aria-hidden>
      <svg
        viewBox="0 0 1600 900"
        preserveAspectRatio="xMidYMax slice"
        className="absolute inset-0 h-full w-full opacity-[0.32]"
      >
        <g opacity="0.5">{spokes}</g>
        {arcs}
      </svg>
      {/* phosphor haze at the horizon */}
      <div
        className="haze-breathe absolute inset-x-0 bottom-0 h-2/3"
        style={{ background: "radial-gradient(60% 70% at 50% 100%, rgba(255,79,46,0.18), transparent 70%)" }}
      />
      {/* fade the top so the headline sits on clean canvas */}
      <div className="absolute inset-x-0 top-0 h-1/3 bg-gradient-to-b from-ink-0 to-transparent" />
    </div>
  );
}
