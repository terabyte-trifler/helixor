import { ArrowUpRight } from "lucide-react";
import type { HistoryEntry } from "@/types/api";
import { TierBadge } from "@/components/score/TierBadge";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/cn";

/**
 * HistoryTable — the per-epoch ledger of an agent's certs.
 *
 * Every row has an explorer link out — partners click these to see the
 * actual on-chain proof. The link target is a placeholder (#) until the
 * SDK provides a `certPda(agent, epoch)` resolver; once it does, swap
 * here.
 */
export function HistoryTable({ entries }: { entries: HistoryEntry[] }) {
  if (entries.length === 0) {
    return (
      <div className="rounded-2xl border border-ink-3 bg-ink-1 p-12 text-center">
        <p className="text-[14px] text-ink-8">
          No history yet — this agent has been seen but not scored in any
          completed epoch.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-ink-3 bg-ink-1 overflow-hidden">
      <div className="grid grid-cols-12 gap-4 px-6 py-3 border-b border-ink-3 bg-ink-2">
        <Th className="col-span-1">Epoch</Th>
        <Th className="col-span-2">Score</Th>
        <Th className="col-span-2">Tier</Th>
        <Th className="col-span-2">Signers</Th>
        <Th className="col-span-3">Computed</Th>
        <Th className="col-span-2 text-right">Cert</Th>
      </div>
      <div>
        {entries.map((e, i) => (
          <div
            key={e.epoch}
            className={cn(
              "grid grid-cols-12 gap-4 items-center px-6 py-3.5",
              i !== entries.length - 1 && "border-b border-ink-3",
              "hover:bg-ink-2 transition-colors",
            )}
          >
            <Td className="col-span-1 font-mono text-ink-12">{e.epoch}</Td>
            <Td className="col-span-2 font-mono text-ink-12 tabular-nums">{e.score}</Td>
            <Td className="col-span-2">
              <TierBadge tier={e.alert_tier} immediateRed={e.immediate_red} size="sm" />
            </Td>
            <Td className="col-span-2 font-mono text-ink-9">
              {e.signer_count} <span className="text-ink-7">/ 5</span>
            </Td>
            <Td className="col-span-3 text-ink-9 text-[13px]">
              {formatRelative(e.computed_at)}
            </Td>
            <Td className="col-span-2 text-right">
              <a
                href="#"
                className="inline-flex items-center gap-1 font-mono text-[12px] text-chain hover:underline"
              >
                explorer
                <ArrowUpRight size={11} />
              </a>
            </Td>
          </div>
        ))}
      </div>
    </div>
  );
}

function Th({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <div className={cn("font-mono text-[10px] tracking-eyebrow uppercase text-ink-7", className)}>
      {children}
    </div>
  );
}

function Td({ className, children }: { className?: string; children: React.ReactNode }) {
  return <div className={cn("text-[13px]", className)}>{children}</div>;
}
