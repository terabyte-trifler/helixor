"use client";

import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/cn";

/**
 * ApproachSteps — the "Steps 01-03 with a live data card" section.
 *
 * Left: three steps; the active one is full-brightness with its body copy
 * expanded, the others dim to ghost weight. Right: a data card swaps with
 * the active step, mono rows with block bars; green marks "the good
 * number" — chart language only, never chrome.
 *
 * Interaction: click to select; auto-advances every 5s until the user
 * interacts (then it's theirs). Reduced-motion users get no auto-advance.
 */

interface StepDef {
  n: string;
  title: string;
  body: string;
  card: { label: string; rows: CardRow[]; footnote: string };
}

interface CardRow {
  name: string;
  bar?: { filled: number; total: number; good?: boolean };
  value: string;
  good?: boolean;
}

const STEPS: StepDef[] = [
  {
    n: "Step 01",
    title: "Observe everything, independently.",
    body:
      "Each node consumes every transaction on Solana and extracts one hundred behavioral features per agent — flow, timing, counterparties, drift against a committed baseline. No node shares inputs with another.",
    card: {
      label: "Feature extraction",
      rows: [
        { name: "features / agent", bar: { filled: 10, total: 10 }, value: "100" },
        { name: "dimensions",       bar: { filled: 5,  total: 10 }, value: "5" },
        { name: "inputs shared between nodes", value: "0", good: true },
        { name: "epoch window",     value: "24h" },
      ],
      footnote: "Five machines, one chain. Same numbers — or someone is lying.",
    },
  },
  {
    n: "Step 02",
    title: "Agree before anything is written.",
    body:
      "Nodes commit their scores under a hash, then reveal. A node that waits to copy its neighbors cannot — the commitment came first. Reveals that deviate from the median are flagged Byzantine and struck.",
    card: {
      label: "Consensus round · epoch 287",
      rows: [
        { name: "commitments sealed", bar: { filled: 5, total: 5 }, value: "5 / 5" },
        { name: "reveals verified",   bar: { filled: 5, total: 5 }, value: "5 / 5" },
        { name: "deviation flagged",  value: "node-2 · 94%" },
        { name: "honest signing set", value: "4 / 5", good: true },
      ],
      footnote: "The liar is excluded automatically. Three strikes invites a slash.",
    },
  },
  {
    n: "Step 03",
    title: "Anchor where no one can edit.",
    body:
      "At least three of five cluster keys sign the certificate digest. Solana's Ed25519 precompile verifies the signatures on-chain — the program refuses to write without them. The cert can only be superseded, never amended.",
    card: {
      label: "Certificate write",
      rows: [
        { name: "signatures required", bar: { filled: 3, total: 5, good: true }, value: "3 of 5", good: true },
        { name: "verified by", value: "Ed25519 precompile" },
        { name: "storage",     value: "per-epoch PDA" },
        { name: "mutability",  value: "none", good: true },
      ],
      footnote: "Immutable once written. Anyone can verify; no one can revise.",
    },
  },
];

/* Deterministic scatter texture behind the card — original generative
 * decoration; fixed positions so SSR and client agree. */
const SCATTER: { x: number; y: number; w: number; o: number }[] = [
  { x: 6,  y: 8,  w: 34, o: 0.5 }, { x: 22, y: 4,  w: 20, o: 0.35 },
  { x: 48, y: 10, w: 44, o: 0.6 }, { x: 71, y: 6,  w: 26, o: 0.4 },
  { x: 12, y: 22, w: 18, o: 0.3 }, { x: 60, y: 24, w: 36, o: 0.5 },
  { x: 84, y: 20, w: 22, o: 0.45 }, { x: 4,  y: 42, w: 28, o: 0.4 },
  { x: 33, y: 38, w: 16, o: 0.3 }, { x: 78, y: 44, w: 40, o: 0.55 },
  { x: 18, y: 60, w: 24, o: 0.35 }, { x: 52, y: 64, w: 30, o: 0.45 },
  { x: 88, y: 62, w: 18, o: 0.3 }, { x: 8,  y: 80, w: 38, o: 0.5 },
  { x: 42, y: 84, w: 20, o: 0.35 }, { x: 68, y: 78, w: 28, o: 0.45 },
];

export function ApproachSteps() {
  const [active, setActive] = useState(0);
  const [userTouched, setUserTouched] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced || userTouched) return;
    timer.current = setInterval(() => {
      setActive((a) => (a + 1) % STEPS.length);
    }, 5000);
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, [userTouched]);

  const step = STEPS[active];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-6 items-start">
      {/* ── Steps list ── */}
      <div className="lg:col-span-5 divide-y divide-ink-3 border-y border-ink-3">
        {STEPS.map((s, i) => {
          const on = i === active;
          return (
            <button
              key={s.n}
              onClick={() => { setActive(i); setUserTouched(true); }}
              className={cn(
                "block w-full text-left py-7 pl-5 pr-4 transition-colors relative",
                on ? "bg-ink-1" : "hover:bg-ink-1/50",
              )}
              aria-pressed={on}
            >
              {on && <span className="absolute left-0 top-0 bottom-0 w-[2px] bg-accent" aria-hidden />}
              <span className={cn(
                "font-mono text-[11px] tracking-eyebrow uppercase",
                on ? "text-accent" : "text-ink-6",
              )}>
                {s.n}
              </span>
              <span className={cn(
                "mt-2 block text-[22px] leading-snug transition-colors",
                on ? "text-ink-12" : "text-ink-6",
              )}>
                {s.title}
              </span>
              <span className={cn(
                "grid transition-all duration-500",
                on ? "grid-rows-[1fr] opacity-100 mt-3" : "grid-rows-[0fr] opacity-0",
              )}>
                <span className="overflow-hidden block text-[14px] leading-[1.7] text-ink-9">
                  {s.body}
                </span>
              </span>
            </button>
          );
        })}
      </div>

      {/* ── Data card over scatter texture ── */}
      <div className="lg:col-span-7 relative min-h-[420px] flex items-center justify-center">
        <div className="absolute inset-0 overflow-hidden" aria-hidden>
          {SCATTER.map((r, i) => (
            <span
              key={i}
              className="absolute h-[7px] rounded-[1px] bg-accent"
              style={{
                left: `${r.x}%`,
                top: `${r.y}%`,
                width: r.w,
                opacity: r.o * 0.45,
              }}
            />
          ))}
        </div>

        <div
          key={active}
          className="relative w-full max-w-md rounded-lg border border-accent/50 bg-ink-1/95 terminal-glow animate-fade-in"
        >
          <div className="px-6 pt-5 pb-4 border-b border-ink-3">
            <span className="font-mono text-[11px] tracking-eyebrow uppercase text-ink-11">
              {step.card.label}
            </span>
          </div>
          <div className="px-6 py-5 space-y-4">
            {step.card.rows.map((row, ri) => (
              <div
                key={row.name}
                className="grid grid-cols-12 gap-3 items-baseline opacity-0 animate-fade-in"
                style={{ animationDelay: `${120 + ri * 90}ms` }}
              >
                <span className="col-span-6 font-mono text-[12px] text-ink-8">
                  {row.name}
                </span>
                <span className="col-span-6 font-mono text-[12.5px] text-right">
                  {row.bar && (
                    <span className={cn("mr-2", row.bar.good ? "text-data-green" : "text-ink-10")} aria-hidden>
                      {"▰".repeat(row.bar.filled)}
                      <span className="text-ink-4">{"▱".repeat(row.bar.total - row.bar.filled)}</span>
                    </span>
                  )}
                  <span className={row.good ? "text-data-green" : "text-ink-12"}>
                    {row.value}
                  </span>
                </span>
              </div>
            ))}
          </div>
          <div className="px-6 pb-5">
            <p className="font-mono text-[11.5px] leading-[1.7] text-ink-7">
              {step.card.footnote}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
