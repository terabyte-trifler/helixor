import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowUpRight, ArrowLeft, Fingerprint, Activity as ActivityIcon, Database, RefreshCw } from "lucide-react";
import { Pill } from "@/components/ui/Pill";
import { getAgentDiagnosis, getAgentHealth, getAgentHistory } from "@/lib/api";
import { ScoreRing } from "@/components/score/ScoreRing";
import { TierBadge } from "@/components/score/TierBadge";
import { DiagnosticPanel } from "@/components/diagnosis/DiagnosticPanel";
import { EvidenceViewer } from "@/components/diagnosis/EvidenceViewer";
import { RemediationHistory } from "@/components/diagnosis/RemediationHistory";
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
    return { title: `${truncateWallet(decoded, 6, 6)} · Phylanx` };
  }
  return {
    title: `${truncateWallet(decoded, 6, 6)} · Score ${health.score} · Phylanx`,
    description: `Phylanx trust score: ${health.score} / 1000 (${health.alert_tier}). Signed by ${health.signer_count} of 5 cluster keys at epoch ${health.epoch}.`,
  };
}

export default async function AgentPage({ params }: PageProps) {
  const { wallet } = await params;
  const decoded = decodeURIComponent(wallet);

  const [health, history, diagnosis] = await Promise.all([
    getAgentHealth(decoded).catch(() => null),
    getAgentHistory(decoded, 30).catch(() => ({
      _v: 1 as const, agent_wallet: decoded, entries: [], from_epoch: null,
      to_epoch: null, limit: 30,
    })),
    getAgentDiagnosis(decoded).catch(() => null),
  ]);

  if (!health) return notFound();
  const flagDisplay = health.flag_set_token
    ? `${health.flag_count ?? 0} fired · ${health.flag_set_token}`
    : `0x${(health.flags ?? 0).toString(16).padStart(8, "0")}`;

  const evidenceSpans = diagnosis?.evidence_spans ?? [];
  const appliedRemediations = diagnosis?.applied_remediations ?? [];
  const hasDiagnosis = diagnosis && diagnosis.decoded_labels.length > 0;

  return (
    <div className="mx-auto max-w-7xl px-6 lg:px-10 py-12 lg:py-16">
      {/* ── Back / breadcrumb ─────────────────────────────────────────── */}
      <Link
        href="/"
        className="inline-flex items-center gap-1.5 text-[13px] text-ink-8 hover:text-ink-12 transition-colors"
      >
        <ArrowLeft size={14} />
        Home
      </Link>

      {/* ── Header rail: wallet + compact score (Day-41 inversion) ───── */}
      {/* The score is no longer the hero. It sits in the header rail as a
          single line of data; the diagnostic panel below is the page's
          centre of gravity. */}
      <header className="mt-6 rounded-2xl border border-ink-3 bg-ink-1 px-6 lg:px-8 py-6">
        <div className="flex items-start justify-between gap-6 flex-wrap">
          <div className="min-w-0">
            <Pill icon={<Fingerprint size={11} strokeWidth={2.5} />}>Agent</Pill>
            <h1 className="mt-2 font-mono text-[18px] lg:text-[22px] text-ink-12 break-all leading-tight">
              {decoded}
            </h1>
            <div className="mt-2 flex items-center gap-3 text-[12px] text-ink-8 flex-wrap">
              <span>Last computed {formatRelative(health.computed_at)}</span>
              <span className="text-ink-5">·</span>
              <span className="font-mono">{formatAbsoluteUTC(health.computed_at)}</span>
              <span className="text-ink-5">·</span>
              <span>Epoch {health.epoch}</span>
              <span className="text-ink-5">·</span>
              <span>Signers {health.signer_count}/5</span>
            </div>
          </div>

          {/* Compact score rail: small ring + number + tier badge.
              Same data as the v1 hero, ~1/4 the footprint. */}
          <div className="flex items-center gap-4 shrink-0">
            <ScoreRing
              score={health.score}
              tier={health.alert_tier}
              size={72}
              strokeWidth={3}
            />
            <div className="flex flex-col items-start gap-1.5">
              <div className="font-mono text-[28px] leading-none text-ink-12 tabular-nums">
                {health.score}
                <span className="text-ink-7 text-[14px] ml-1">/ 1000</span>
              </div>
              <TierBadge tier={health.alert_tier} immediateRed={health.immediate_red} size="sm" />
            </div>
          </div>
        </div>
      </header>

      {/* ── Diagnostic panel — primary content ────────────────────────── */}
      {diagnosis && (
        <div className="mt-8">
          <DiagnosticPanel diagnosis={diagnosis} />
        </div>
      )}

      {/* ── Evidence viewer — Day 41 ─────────────────────────────────── */}
      {hasDiagnosis && (
        <div className="mt-8">
          <EvidenceViewer
            attestation={diagnosis.attestation}
            labels={diagnosis.decoded_labels}
            spans={evidenceSpans}
          />
        </div>
      )}

      {/* ── Remediation history (recovering-agent story) ─────────────── */}
      {appliedRemediations.length > 0 && (
        <div className="mt-8">
          <RemediationHistory entries={appliedRemediations} />
        </div>
      )}

      {/* ── Certificate details — collapsed below the diagnosis ──────── */}
      <details className="mt-10 group rounded-2xl border border-ink-3 bg-ink-1">
        <summary className="cursor-pointer list-none px-6 lg:px-8 py-5 flex items-center justify-between gap-4">
          <div>
            <span className="eyebrow-accent">On-chain certificate</span>
            <h3 className="mt-1 text-[16px] text-ink-12">Cert details</h3>
          </div>
          <span className="text-[12px] font-mono text-ink-9 group-open:hidden">
            expand
          </span>
          <span className="text-[12px] font-mono text-ink-9 hidden group-open:inline">
            collapse
          </span>
        </summary>
        <div className="border-t border-ink-3 px-6 lg:px-8 py-6 grid grid-cols-1 sm:grid-cols-2 gap-x-10 gap-y-5">
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
              <span className="font-mono text-[13px] text-ink-12 break-all">
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
          <div className="sm:col-span-2 pt-5 border-t border-ink-3">
            <span className="eyebrow-accent">Cert digest</span>
            <div className="mt-2 flex items-center gap-3 flex-wrap">
              <code className="font-mono text-[12px] text-accent bg-ink-2 px-3 py-1.5 rounded-md border border-ink-3">
                5sP1d…q3J7m
              </code>
              <a href="#" className="text-[12px] text-ink-9 hover:text-ink-12 inline-flex items-center gap-1">
                Open in Solscan <ArrowUpRight size={11} />
              </a>
            </div>
          </div>
        </div>
      </details>

      {/* ── History chart ─────────────────────────────────────────────── */}
      <div className="mt-12">
        <div className="flex items-end justify-between mb-6">
          <div>
            <Pill icon={<ActivityIcon size={11} strokeWidth={2.5} />}>Score history</Pill>
            <h2 className="mt-2 text-[22px] text-ink-12 tracking-tight">
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
        <Pill icon={<Database size={11} strokeWidth={2.5} />}>Every cert</Pill>
        <h2 className="mt-2 text-[22px] text-ink-12 tracking-tight">
          On-chain ledger
        </h2>
        <div className="mt-6">
          <HistoryTable entries={history.entries} />
        </div>
      </div>

      {/* ── Score another ─────────────────────────────────────────────── */}
      <div className="mt-20 pt-16 border-t border-ink-3">
        <Pill icon={<RefreshCw size={11} strokeWidth={2.5} />}>Try another</Pill>
        <h2 className="mt-2 text-[22px] text-ink-12 tracking-tight max-w-[24ch]">
          Diagnose another agent.
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
      <span className="eyebrow-accent shrink-0">{label}</span>
      <div className="text-[14px] font-mono text-ink-12 tabular-nums text-right">
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
