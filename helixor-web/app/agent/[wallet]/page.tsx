import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowUpRight, ArrowLeft } from "lucide-react";
import { getAgentHealth, getAgentHistory } from "@/lib/api";
import { ScoreRing } from "@/components/score/ScoreRing";
import { TierBadge } from "@/components/score/TierBadge";
import { HistorySpark } from "@/components/charts/HistorySpark";
import { HistoryTable } from "@/components/data/HistoryTable";
import { LookupBar } from "@/components/lookup/LookupBar";
import { formatAbsoluteUTC, formatRelative, truncateWallet } from "@/lib/format";
import { cn } from "@/lib/cn";
import type { Metadata } from "next";

interface PageProps {
  params: Promise<{ wallet: string }>;
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { wallet } = await params;
  const decoded = decodeURIComponent(wallet);
  const health = await getAgentHealth(decoded).catch(() => null);
  if (!health) {
    return { title: `${truncateWallet(decoded, 6, 6)} · Helixor` };
  }
  return {
    title: `${truncateWallet(decoded, 6, 6)} · Score ${health.score} · Helixor`,
    description: `Helixor trust score: ${health.score} / 1000 (${health.alert_tier}). Signed by ${health.signer_count} of 5 cluster keys at epoch ${health.epoch}.`,
  };
}

export default async function AgentPage({ params }: PageProps) {
  const { wallet } = await params;
  const decoded = decodeURIComponent(wallet);

  const [health, history] = await Promise.all([
    getAgentHealth(decoded).catch(() => null),
    getAgentHistory(decoded, 30).catch(() => ({
      _v: 1 as const, agent_wallet: decoded, entries: [], from_epoch: null,
      to_epoch: null, limit: 30,
    })),
  ]);

  if (!health) return notFound();
  const flagDisplay = health.flag_set_token
    ? `${health.flag_count ?? 0} fired · ${health.flag_set_token}`
    : `0x${(health.flags ?? 0).toString(16).padStart(8, "0")}`;

  return (
    <div className="mx-auto max-w-7xl px-6 lg:px-10 py-16 lg:py-20">
      {/* ── Back / breadcrumb ─────────────────────────────────────────── */}
      <Link
        href="/"
        className="inline-flex items-center gap-1.5 text-[13px] text-ink-8 hover:text-ink-12 transition-colors"
      >
        <ArrowLeft size={14} />
        Home
      </Link>

      {/* ── Wallet header ─────────────────────────────────────────────── */}
      <div className="mt-6 flex items-start justify-between gap-6 flex-wrap">
        <div>
          <span className="eyebrow">Agent</span>
          <h1 className="mt-2 font-mono text-[22px] lg:text-[28px] text-ink-12 break-all">
            {decoded}
          </h1>
          <div className="mt-2 flex items-center gap-3 text-[13px] text-ink-8">
            <span>Last computed {formatRelative(health.computed_at)}</span>
            <span className="text-ink-5">·</span>
            <span className="font-mono">{formatAbsoluteUTC(health.computed_at)}</span>
          </div>
        </div>
        <a
          href="#"
          className={cn(
            "inline-flex items-center gap-1.5 h-9 px-4 rounded-full",
            "border border-ink-4 text-[13px] text-ink-10 hover:text-ink-12 hover:border-ink-6",
            "transition-colors",
          )}
        >
          View on Solscan
          <ArrowUpRight size={13} />
        </a>
      </div>

      {/* ── Score card ────────────────────────────────────────────────── */}
      <div className="mt-12 rounded-3xl border border-ink-3 bg-ink-1 overflow-hidden">
        <div className="grid grid-cols-1 lg:grid-cols-12">
          {/* Score ring */}
          <div className="lg:col-span-5 p-10 lg:p-14 flex flex-col items-center justify-center border-b lg:border-b-0 lg:border-r border-ink-3">
            <ScoreRing
              score={health.score}
              tier={health.alert_tier}
              size={280}
              strokeWidth={4}
            >
              <div className="font-mono text-[6.5rem] leading-none text-ink-12 tabular-nums">
                {health.score}
              </div>
              <div className="font-mono text-[11px] tracking-eyebrow uppercase text-ink-7 mt-2">
                of 1000
              </div>
            </ScoreRing>
            <div className="mt-8">
              <TierBadge tier={health.alert_tier} immediateRed={health.immediate_red} />
            </div>
          </div>

          {/* Right side: cert details */}
          <div className="lg:col-span-7 p-10 lg:p-14">
            <div className="space-y-8">
              <DetailRow label="Epoch" value={health.epoch} />
              <DetailRow
                label="Signers"
                value={
                  <>
                    {health.signer_count}{" "}
                    <span className="text-ink-7">/ 5 cluster keys</span>
                  </>
                }
              />
              <DetailRow
                label="Flags"
                value={
                  <span className="font-mono text-[14px] text-ink-12 break-all">
                    {flagDisplay}
                  </span>
                }
              />
              <DetailRow
                label="Immediate red"
                value={
                  health.immediate_red ? (
                    <span className="text-tier-red">YES</span>
                  ) : (
                    <span className="text-ink-9">no</span>
                  )
                }
              />
              <div className="pt-8 border-t border-ink-3">
                <span className="eyebrow">On-chain certificate</span>
                <div className="mt-4 flex items-center gap-3 flex-wrap">
                  <code className="font-mono text-[13px] text-chain bg-ink-2 px-3 py-1.5 rounded-md border border-ink-3">
                    5sP1d…q3J7m
                  </code>
                  <a href="#" className="text-[13px] text-ink-9 hover:text-ink-12 inline-flex items-center gap-1">
                    Open in Solscan <ArrowUpRight size={12} />
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── History chart ─────────────────────────────────────────────── */}
      <div className="mt-16">
        <div className="flex items-end justify-between mb-6">
          <div>
            <span className="eyebrow">Score history</span>
            <h2 className="mt-2 text-[24px] text-ink-12 tracking-tight">
              Last 30 epochs
            </h2>
          </div>
          <div className="flex items-center gap-4 text-[11px] font-mono text-ink-7 tracking-eyebrow uppercase">
            <LegendDot color="#34d399" label="≥ 800 green" />
            <LegendDot color="#fbbf24" label="≥ 400 yellow" />
            <LegendDot color="#f87171" label="< 400 red" />
          </div>
        </div>
        <div className="rounded-2xl border border-ink-3 bg-ink-1 p-6 pb-2">
          <HistorySpark entries={history.entries} />
        </div>
      </div>

      {/* ── History table ─────────────────────────────────────────────── */}
      <div className="mt-12">
        <span className="eyebrow">Every cert</span>
        <h2 className="mt-2 text-[24px] text-ink-12 tracking-tight">
          On-chain ledger
        </h2>
        <div className="mt-6">
          <HistoryTable entries={history.entries} />
        </div>
      </div>

      {/* ── Score another ─────────────────────────────────────────────── */}
      <div className="mt-20 pt-16 border-t border-ink-3">
        <span className="eyebrow">Try another</span>
        <h2 className="mt-2 text-[24px] text-ink-12 tracking-tight max-w-[24ch]">
          Score another agent.
        </h2>
        <div className="mt-8">
          <LookupBar />
        </div>
      </div>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-6">
      <span className="eyebrow shrink-0">{label}</span>
      <div className="text-[15px] font-mono text-ink-12 tabular-nums text-right">
        {value}
      </div>
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ background: color }}
      />
      {label}
    </span>
  );
}
