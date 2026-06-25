"use client";

import Link from "next/link";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { ArrowUpRight } from "lucide-react";
import { cn } from "@/lib/cn";

/**
 * AgentShowcase — the tabbed product demo.
 *
 * Four tabs, one per demo agent. The underline slides between tabs; the
 * panel cross-fades: three cert findings on the left, a compact
 * certificate card on the right. Auto-cycles every 5s until the visitor
 * interacts — the demo demos itself, then hands over the controls.
 *
 * Display data mirrors lib/mock.ts so the cards match what the agent
 * pages serve when a tab's "view full cert" link is followed.
 */

interface AgentDef {
  tab: string;
  wallet: string;
  score: number;
  tier: "GREEN" | "YELLOW" | "RED";
  signers: string;
  findings: string[];
  verdict: string;
}

const AGENTS: AgentDef[] = [
  {
    tab: "Stable arb bot",
    wallet: "Hxr1Demo01StableTrader1111111111111111111111",
    score: 941,
    tier: "GREEN",
    signers: "3 / 5",
    findings: [
      "Tight spread discipline held across thirty straight epochs.",
      "Counterparty set stable — no concentration flags raised.",
      "Baseline drift: none detected on any dimension.",
    ],
    verdict: "Route freely.",
  },
  {
    tab: "Yield agent",
    wallet: "Hxr2Demo02RecoveringYieldAgent11111111111111",
    score: 712,
    tier: "YELLOW",
    signers: "3 / 5",
    findings: [
      "Dipped on a strategy change — and the cluster saw it happen.",
      "Recovering trend across seventeen consecutive epochs.",
      "Two consistency flags, both clearing as cadence returns.",
    ],
    verdict: "Improving. Watch the trend.",
  },
  {
    tab: "MM strategy",
    wallet: "Hxr3Demo03DriftingMarketMaker111111111111111",
    score: 583,
    tier: "YELLOW",
    signers: "4 / 5",
    findings: [
      "Quote rhythm broken — cadence shifted from its baseline.",
      "Counterparty flip flagged at epoch 281, still unresolved.",
      "Held at watch tier until the drift stabilizes.",
    ],
    verdict: "Caution tier. Verify before sizing up.",
  },
  {
    tab: "Compromised agent",
    wallet: "Hxr4Demo04FlaggedExfilAgent1111111111111111x",
    score: 184,
    tier: "RED",
    signers: "4 / 5",
    findings: [
      "IMMEDIATE RED — outflow velocity spiked beyond tolerance.",
      "Unknown program set appeared after epoch 285.",
      "The certificate says what the signature can't: do not route.",
    ],
    verdict: "Do not route.",
  },
];

const TIER_STYLE: Record<AgentDef["tier"], { text: string; dot: string; border: string }> = {
  GREEN:  { text: "text-tier-green",  dot: "bg-tier-green",  border: "border-tier-green/40" },
  YELLOW: { text: "text-tier-yellow", dot: "bg-tier-yellow", border: "border-tier-yellow/40" },
  RED:    { text: "text-tier-red",    dot: "bg-tier-red",    border: "border-tier-red/40" },
};

export function AgentShowcase() {
  const [active, setActive] = useState(0);
  const [touched, setTouched] = useState(false);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const [bar, setBar] = useState({ left: 0, width: 0 });

  // Auto-cycle until the visitor takes over.
  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced || touched) return;
    const id = setInterval(() => setActive((a) => (a + 1) % AGENTS.length), 5000);
    return () => clearInterval(id);
  }, [touched]);

  // Slide the underline to the active tab.
  useLayoutEffect(() => {
    const update = () => {
      const el = tabRefs.current[active];
      if (el) setBar({ left: el.offsetLeft, width: el.offsetWidth });
    };
    update();
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, [active]);

  const agent = AGENTS[active];
  const tier = TIER_STYLE[agent.tier];

  return (
    <div>
      {/* ── Tabs ── */}
      <div className="relative border-b border-ink-3 overflow-x-auto">
        <div className="flex gap-1 min-w-max">
          {AGENTS.map((a, i) => (
            <button
              key={a.wallet}
              ref={(el) => { tabRefs.current[i] = el; }}
              onClick={() => { setActive(i); setTouched(true); }}
              className={cn(
                "px-5 py-3.5 text-[13.5px] whitespace-nowrap transition-colors",
                i === active ? "text-ink-12" : "text-ink-7 hover:text-ink-10",
              )}
              aria-pressed={i === active}
            >
              <span className={cn(
                "inline-block h-1.5 w-1.5 rounded-full mr-2 align-middle",
                TIER_STYLE[a.tier].dot,
                i === active ? "opacity-100" : "opacity-40",
              )} aria-hidden />
              {a.tab}
            </button>
          ))}
        </div>
        <span
          className="tab-underline absolute bottom-0 h-[2px] bg-accent"
          style={{ transform: `translateX(${bar.left}px)`, width: bar.width }}
          aria-hidden
        />
      </div>

      {/* ── Panel — cross-fades on tab change ── */}
      <div key={active} className="mt-10 grid grid-cols-1 lg:grid-cols-12 gap-10 panel-rise">
        <div className="lg:col-span-6 space-y-7">
          {agent.findings.map((f, i) => (
            <div
              key={f}
              className="flex gap-4 opacity-0 animate-fade-in"
              style={{ animationDelay: `${100 + i * 110}ms` }}
            >
              <span className="font-mono text-[11px] text-accent tabular-nums pt-1 shrink-0">
                {String(i + 1).padStart(2, "0")}
              </span>
              <p className="text-[15px] leading-[1.7] text-ink-10">{f}</p>
            </div>
          ))}
          <div
            className="opacity-0 animate-fade-in pl-9"
            style={{ animationDelay: "440ms" }}
          >
            <span className="font-mono text-[12px] tracking-wide uppercase text-ink-7">
              cluster verdict —{" "}
            </span>
            <span className={cn("font-mono text-[12px] tracking-wide uppercase", tier.text)}>
              {agent.verdict}
            </span>
          </div>
        </div>

        {/* The compact certificate card */}
        <div className="lg:col-span-6">
          <div className={cn("rounded-lg border bg-ink-1", tier.border)}>
            <div className="flex items-center justify-between px-6 py-4 border-b border-ink-3">
              <span className="font-mono text-[11.5px] text-ink-8 truncate max-w-[60%]">
                {agent.wallet.slice(0, 10)}…{agent.wallet.slice(-4)}
              </span>
              <span className="flex items-center gap-2 font-mono text-[11px] tracking-eyebrow uppercase">
                <span className={cn("h-1.5 w-1.5 rounded-full", tier.dot)} aria-hidden />
                <span className={tier.text}>{agent.tier}</span>
              </span>
            </div>
            <div className="px-6 py-7 flex items-end justify-between">
              <div>
                <div className="font-mono text-[64px] leading-none text-ink-12 tabular-nums">
                  {agent.score}
                </div>
                <div className="mt-2 font-mono text-[11px] tracking-eyebrow uppercase text-ink-7">
                  of 1000 · epoch 287
                </div>
              </div>
              <div className="text-right space-y-2">
                <div className="font-mono text-[12px] text-ink-9">
                  signers <span className="text-ink-12">{agent.signers}</span>
                </div>
                <div className="font-mono text-[12px] text-ink-9">
                  threshold <span className="text-ink-12">3 of 5</span>
                </div>
              </div>
            </div>
            <div className="px-6 py-4 border-t border-ink-3">
              <Link
                href={`/agent/${agent.wallet}`}
                className="inline-flex items-center gap-1.5 font-mono text-[12.5px] text-accent hover:text-accent-bright transition-colors"
              >
                view full certificate <ArrowUpRight size={13} />
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
