"use client";

import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/cn";

/**
 * Terminal — the signature element of the landing page.
 *
 * A faux terminal that boots an oracle node, runs one epoch end-to-end,
 * catches a Byzantine node, and anchors a cert. The whole protocol story
 * in nine lines of original copy, told in the product's native voice.
 *
 * The boot sequence types itself out once on mount (line-by-line, not
 * char-by-char — chars read as gimmick, lines read as logs). Respects
 * prefers-reduced-motion by rendering everything instantly.
 */

interface Line {
  text: string;
  tone: "cmd" | "dim" | "plain" | "ok" | "warn";
}

const BOOT: Line[] = [
  { text: "$ phylanx node start --network devnet",                 tone: "cmd"   },
  { text: "keypair loaded · oracle-node-3",                        tone: "dim"   },
  { text: "peers 5/5 · threshold 3-of-5 · epoch 287",              tone: "plain" },
  { text: "commit phase ─ 5 commitments sealed",                   tone: "plain" },
  { text: "reveal phase ─ 5 reveals verified",                     tone: "plain" },
  { text: "byzantine check ─ node-2 deviates 94% → flagged",       tone: "warn"  },
  { text: "consensus ─ median 851 · signing set 4/5",              tone: "plain" },
  { text: "✓ cert 5sP1…q3J7 anchored · slot 312,448,901",          tone: "ok"    },
  { text: "network devnet · telemetry none · trust math",          tone: "dim"   },
];

const TONE_CLASS: Record<Line["tone"], string> = {
  cmd:   "text-accent-bright",
  dim:   "text-ink-7",
  plain: "text-ink-10",
  ok:    "text-accent",
  warn:  "text-tier-yellow",
};

export function Terminal({ className }: { className?: string }) {
  const [shown, setShown] = useState(0);
  const done = shown >= BOOT.length;
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) {
      setShown(BOOT.length);
      return;
    }
    let i = 0;
    function next() {
      i += 1;
      setShown(i);
      if (i < BOOT.length) {
        // Slight rhythm: the command lands fast, phases take a beat,
        // the cert line gets a dramatic pause before it.
        const delay = i === BOOT.length - 2 ? 700 : 360;
        timer.current = setTimeout(next, delay);
      }
    }
    timer.current = setTimeout(next, 500);
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  return (
    <div
      className={cn(
        "rounded-2xl border border-ink-4 bg-ink-1 overflow-hidden terminal-glow",
        className,
      )}
      role="img"
      aria-label="Terminal: a Phylanx oracle node runs one scoring epoch, flags a deviating node, and anchors a threshold-signed certificate on-chain"
    >
      {/* Title bar */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-ink-3 bg-ink-2">
        <div className="flex items-center gap-1.5" aria-hidden>
          <span className="h-2.5 w-2.5 rounded-full bg-ink-5" />
          <span className="h-2.5 w-2.5 rounded-full bg-ink-5" />
          <span className="h-2.5 w-2.5 rounded-full bg-ink-5" />
        </div>
        <span className="font-mono text-[11px] tracking-eyebrow uppercase text-ink-7">
          phylanx://devnet · oracle-node-3
        </span>
      </div>

      {/* Log body */}
      <div className="px-5 py-5 min-h-[280px]">
        <pre className="font-mono text-[13px] leading-[1.9] whitespace-pre-wrap">
          {BOOT.slice(0, shown).map((line, i) => (
            <div key={i} className={cn(TONE_CLASS[line.tone], "animate-fade-in")}>
              {line.tone !== "cmd" && line.tone !== "dim" ? (
                <span className="text-ink-6 select-none">{"▸ "}</span>
              ) : null}
              {line.text}
            </div>
          ))}
          {done && (
            <div className="text-accent-bright">
              {"$ "}
              <span className="inline-block w-[8px] h-[15px] translate-y-[2px] bg-accent-bright animate-blink" />
            </div>
          )}
        </pre>
      </div>
    </div>
  );
}
