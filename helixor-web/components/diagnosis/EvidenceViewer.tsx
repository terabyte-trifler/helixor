/**
 * components/diagnosis/EvidenceViewer.tsx — Day 41.
 *
 * The "diagnosis is the product" surface. Per-label expandable rows;
 * each label opens a list of evidence spans (slot anchor, optional tx
 * signature with explorer link, one-line summary, digest hex). The
 * attestation badge at the top tells the operator whether they are
 * looking at off-chain Phase-1 evidence or the threshold-attested
 * Phase-2 path.
 *
 * Monochrome discipline: the only chromatic element is the attestation
 * dot. Severity tags reuse the same ink+tier styling as DiagnosticPanel.
 */

"use client";

import { useState } from "react";
import { ArrowUpRight, ChevronRight, Hash } from "lucide-react";
import { cn } from "@/lib/cn";
import { severityClass } from "@/lib/taxonomy";
import type {
  DecodedFlagLabel,
  DiagnosisAttestation,
  EvidenceSpan,
} from "@/types/api";

interface EvidenceViewerProps {
  attestation: DiagnosisAttestation;
  labels: DecodedFlagLabel[];
  spans: EvidenceSpan[];
  explorerBaseUrl?: string; // defaults to solscan
}

const DEFAULT_EXPLORER = "https://solscan.io/tx";

export function EvidenceViewer({
  attestation,
  labels,
  spans,
  explorerBaseUrl = DEFAULT_EXPLORER,
}: EvidenceViewerProps) {
  const byLabelBit = new Map<number, EvidenceSpan[]>();
  for (const span of spans) {
    const list = byLabelBit.get(span.label_bit) ?? [];
    list.push(span);
    byLabelBit.set(span.label_bit, list);
  }
  // Sort spans by index within each label.
  for (const list of byLabelBit.values()) {
    list.sort((a, b) => a.span_index - b.span_index);
  }

  const labelsWithEvidence = labels.filter((l) => byLabelBit.has(l.bit));
  const labelsWithoutEvidence = labels.filter((l) => !byLabelBit.has(l.bit));

  return (
    <section
      aria-label="Evidence viewer"
      className="rounded-3xl border border-ink-3 bg-ink-1 overflow-hidden"
    >
      <header className="px-8 lg:px-12 pt-10 pb-6 border-b border-ink-3 flex items-end justify-between gap-6 flex-wrap">
        <div>
          <span className="eyebrow">Evidence</span>
          <h2 className="mt-2 text-[24px] lg:text-[28px] text-ink-12 tracking-tight">
            Cite, don&apos;t claim
          </h2>
          <p className="mt-2 text-[13px] text-ink-8 max-w-[56ch]">
            Every label expands into the spans the cluster observed.
            Slot anchors and transaction signatures are clickable.
          </p>
        </div>
        <AttestationBadge attestation={attestation} />
      </header>

      <div className="px-8 lg:px-12 py-8">
        {labelsWithEvidence.length === 0 && labelsWithoutEvidence.length === 0 ? (
          <EmptyState />
        ) : (
          <ul className="space-y-3">
            {labelsWithEvidence.map((label) => (
              <LabelRow
                key={label.bit}
                label={label}
                spans={byLabelBit.get(label.bit) ?? []}
                explorerBaseUrl={explorerBaseUrl}
              />
            ))}
            {labelsWithoutEvidence.map((label) => (
              <LabelRow
                key={label.bit}
                label={label}
                spans={[]}
                explorerBaseUrl={explorerBaseUrl}
              />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Row
// ─────────────────────────────────────────────────────────────────────────────

function LabelRow({
  label,
  spans,
  explorerBaseUrl,
}: {
  label: DecodedFlagLabel;
  spans: EvidenceSpan[];
  explorerBaseUrl: string;
}) {
  const [open, setOpen] = useState(spans.length > 0 && label.severity === "CRITICAL");
  const hasSpans = spans.length > 0;
  return (
    <li className="rounded-2xl border border-ink-3 bg-ink-2 overflow-hidden">
      <button
        type="button"
        onClick={() => hasSpans && setOpen((v) => !v)}
        disabled={!hasSpans}
        className={cn(
          "w-full flex items-center justify-between gap-4 px-5 py-4",
          "text-left transition-colors",
          hasSpans ? "hover:bg-ink-3 cursor-pointer" : "cursor-default",
        )}
        aria-expanded={open}
      >
        <div className="flex items-center gap-3 min-w-0">
          <ChevronRight
            size={14}
            className={cn(
              "shrink-0 text-ink-7 transition-transform",
              hasSpans ? "" : "opacity-30",
              open && "rotate-90",
            )}
          />
          <span
            className={cn(
              "shrink-0 inline-flex items-center rounded-full border px-2.5 py-0.5",
              "font-mono text-[10px] tracking-eyebrow uppercase",
              severityClass(label.severity),
            )}
          >
            {label.severity}
          </span>
          <span className="font-mono text-[13px] text-ink-12 truncate">
            {label.name}
          </span>
        </div>
        <div className="shrink-0 flex items-center gap-3 text-[11px] font-mono tracking-eyebrow uppercase text-ink-7">
          <span>bit {label.bit}</span>
          {hasSpans ? (
            <span className="text-ink-9">
              {spans.length} span{spans.length === 1 ? "" : "s"}
            </span>
          ) : (
            <span>no span</span>
          )}
        </div>
      </button>
      {open && hasSpans && (
        <div className="border-t border-ink-3 bg-ink-1">
          <p className="px-5 pt-4 pb-2 text-[12px] text-ink-9 leading-relaxed max-w-[68ch]">
            {label.description}
          </p>
          <ul className="px-5 pb-5 pt-2 space-y-2">
            {spans.map((s) => (
              <SpanRow
                key={`${s.label_bit}:${s.span_index}`}
                span={s}
                explorerBaseUrl={explorerBaseUrl}
              />
            ))}
          </ul>
        </div>
      )}
    </li>
  );
}

function SpanRow({
  span,
  explorerBaseUrl,
}: {
  span: EvidenceSpan;
  explorerBaseUrl: string;
}) {
  return (
    <li className="rounded-lg border border-ink-3 bg-ink-2 px-4 py-3">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[11px] font-mono tracking-eyebrow uppercase text-ink-7">
            <span>{span.evidence_kind}</span>
            <span className="text-ink-5">·</span>
            <span>slot {span.slot.toLocaleString()}</span>
          </div>
          <p className="mt-1 text-[13px] text-ink-12 leading-relaxed">
            {span.summary}
          </p>
          <div className="mt-2 flex items-center gap-2 text-[11px] font-mono text-ink-7">
            <Hash size={10} />
            <span className="truncate max-w-[28ch]" title={span.digest_hex}>
              {span.digest_hex.slice(0, 12)}…{span.digest_hex.slice(-8)}
            </span>
          </div>
        </div>
        {span.tx_signature ? (
          <a
            href={`${explorerBaseUrl}/${span.tx_signature}`}
            target="_blank"
            rel="noopener noreferrer"
            className={cn(
              "shrink-0 inline-flex items-center gap-1 text-[12px] text-chain",
              "hover:underline",
            )}
          >
            tx <ArrowUpRight size={11} />
          </a>
        ) : (
          <span className="shrink-0 text-[11px] font-mono tracking-eyebrow uppercase text-ink-7">
            observational
          </span>
        )}
      </div>
    </li>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Attestation badge — Day-41 expansion of the Phase-1 pill on
// DiagnosticPanel. Visually distinct here because evidence is the
// piece the auditor verifies, so the trust mode is the headline.
// ─────────────────────────────────────────────────────────────────────────────

const ATTESTATION_META: Record<
  DiagnosisAttestation,
  { label: string; dot: string; blurb: string }
> = {
  off_chain_v1: {
    label: "off-chain · v1",
    dot: "bg-ink-7",
    blurb:
      "Phase-1: faithful to the oracle's epoch_runner output but not yet threshold-signed.",
  },
  cert_v2: {
    label: "cert-v2 · threshold-signed",
    dot: "bg-tier-green",
    blurb:
      "Phase-2: every label bit is part of the canonical cert digest, threshold-signed by the cluster.",
  },
  threshold_attested: {
    label: "threshold-attested · DA",
    dot: "bg-tier-green",
    blurb:
      "Evidence bytes are bound to the cert by SHA-256 and the digest is threshold-signed.",
  },
};

function AttestationBadge({
  attestation,
}: {
  attestation: DiagnosisAttestation;
}) {
  const meta = ATTESTATION_META[attestation];
  return (
    <span
      title={meta.blurb}
      className={cn(
        "inline-flex items-center gap-2 rounded-full border border-ink-4",
        "bg-ink-2 px-3 py-1.5 font-mono text-[11px] tracking-eyebrow uppercase",
        "text-ink-10",
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", meta.dot)} />
      Attestation · {meta.label}
    </span>
  );
}

function EmptyState() {
  return (
    <div className="rounded-xl border border-ink-3 bg-ink-2 px-6 py-10 text-center">
      <p className="text-[14px] text-ink-9">
        No labels fired this epoch — no evidence to cite.
      </p>
      <p className="mt-1 text-[12px] text-ink-7">
        The diagnosis is clean.
      </p>
    </div>
  );
}
