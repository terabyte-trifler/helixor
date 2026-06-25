/**
 * components/diagnosis/RemediationHistory.tsx — Day 41.
 *
 * The "this agent's operator has been doing the work" surface, rendered
 * on the recovering-agent story. Lists the remediations that have ALREADY
 * been applied across recent epochs (with outcome), so the panel reads
 * as ledger, not as hint.
 *
 * Distinct from the DiagnosticPanel's "Suggested remediation" — that
 * section says what to do; this one says what was already done.
 */

import { Check, Clock, RotateCcw } from "lucide-react";
import { cn } from "@/lib/cn";
import type { AppliedRemediation } from "@/types/api";

interface RemediationHistoryProps {
  entries: AppliedRemediation[];
}

const OUTCOME_META: Record<
  AppliedRemediation["outcome"],
  { icon: React.ReactNode; tone: string; label: string }
> = {
  in_progress: {
    icon: <Clock size={12} />,
    tone: "text-ink-9 border-ink-4 bg-ink-2",
    label: "in progress",
  },
  succeeded: {
    icon: <Check size={12} />,
    tone: "text-tier-green border-tier-green/30 bg-tier-green/[0.06]",
    label: "succeeded",
  },
  rolled_back: {
    icon: <RotateCcw size={12} />,
    tone: "text-tier-yellow border-tier-yellow/30 bg-tier-yellow/[0.06]",
    label: "rolled back",
  },
};

export function RemediationHistory({ entries }: RemediationHistoryProps) {
  const sorted = [...entries].sort(
    (a, b) => b.applied_at_epoch - a.applied_at_epoch,
  );

  return (
    <section
      aria-label="Remediation history"
      className="rounded-3xl border border-ink-3 bg-ink-1 overflow-hidden"
    >
      <header className="px-8 lg:px-12 pt-10 pb-6 border-b border-ink-3">
        <span className="eyebrow">Remediation history</span>
        <h2 className="mt-2 text-[22px] lg:text-[26px] text-ink-12 tracking-tight">
          What the operator already did
        </h2>
        <p className="mt-2 text-[13px] text-ink-8 max-w-[56ch]">
          Applied remediations from prior epochs, with outcome. The
          suggestion list on the panel above is hints — this is ledger.
        </p>
      </header>

      <ul className="divide-y divide-ink-3">
        {sorted.map((entry) => {
          const meta = OUTCOME_META[entry.outcome];
          return (
            <li
              key={`${entry.bit}:${entry.applied_at_epoch}`}
              className="px-8 lg:px-12 py-5 flex items-start justify-between gap-6 flex-wrap"
            >
              <div className="min-w-0">
                <div className="flex items-center gap-3 flex-wrap">
                  <span className="font-mono text-[13px] text-ink-12">
                    {entry.name}
                  </span>
                  <span className="text-[10px] font-mono tracking-eyebrow uppercase text-ink-7">
                    bit {entry.bit}
                  </span>
                  <span className="text-[11px] font-mono text-ink-9">
                    epoch {entry.applied_at_epoch}
                  </span>
                </div>
                <p className="mt-1.5 text-[12px] text-ink-9 leading-relaxed max-w-[64ch]">
                  {entry.note}
                </p>
              </div>
              <span
                className={cn(
                  "shrink-0 inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1",
                  "font-mono text-[10px] tracking-eyebrow uppercase",
                  meta.tone,
                )}
              >
                {meta.icon}
                {meta.label}
              </span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
