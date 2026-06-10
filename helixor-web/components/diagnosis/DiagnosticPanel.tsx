/**
 * components/diagnosis/DiagnosticPanel.tsx — the "score → diagnosis"
 * moment in the UI.
 *
 * The panel sits below the ScoreRing card on /agent/[wallet]. It surfaces:
 *
 *  1. FIVE dimension bars (drift / anomaly / performance / consistency /
 *     security) — each shows raw points-out-of-cap plus the weighted
 *     contribution to the composite. Bars are monochrome (ink fill, ink-12
 *     accent for "earned"); only the alert tier and the severity chips
 *     carry color.
 *
 *  2. Flag chips grouped by severity (CRITICAL / HIGH / MED / LOW / INFO).
 *     Each chip shows the failure-mode name + a hover description. The
 *     OWASP refs ride along quietly underneath. This is the moment where
 *     the user moves from "the score is low" to "here is WHY".
 *
 *  3. A remediation list (max 6 surfaced) — the actions the playbook
 *     suggests if these labels were the diagnosis. Day-34 is HINTS only,
 *     so the section is labelled "Suggested remediation" — not a verdict.
 *
 * Monochrome discipline holds throughout. The only chromatic elements
 * are the tier color on the header pill, the severity chip rings, and
 * the dim earned-portion accent. No icon color, no link color.
 */

import { Info } from "lucide-react";
import { cn } from "@/lib/cn";
import { severityClass } from "@/lib/taxonomy";
import type {
  DecodedFlagLabel,
  DiagnosisResponse,
  DimensionBreakdownEntry,
  Severity,
} from "@/types/api";

interface DiagnosticPanelProps {
  diagnosis: DiagnosisResponse;
}

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MED", "LOW", "INFO"];

const DIMENSION_LABELS: Record<string, { title: string; blurb: string }> = {
  drift: {
    title: "Drift",
    blurb: "Distance from the agent's baseline distribution.",
  },
  anomaly: {
    title: "Anomaly",
    blurb: "Per-output outlier signal across the epoch's traces.",
  },
  performance: {
    title: "Performance",
    blurb: "Risk-adjusted return vs. declared strategy envelope.",
  },
  consistency: {
    title: "Consistency",
    blurb: "Predictability of behaviour across epochs.",
  },
  security: {
    title: "Security",
    blurb: "Tool, identity, and supply-chain integrity checks.",
  },
};

export function DiagnosticPanel({ diagnosis }: DiagnosticPanelProps) {
  const grouped = groupBySeverity(diagnosis.decoded_labels);
  const hasFlags = diagnosis.decoded_labels.length > 0;

  return (
    <section
      aria-label="Diagnostic breakdown"
      className="rounded-3xl border border-ink-3 bg-ink-1 overflow-hidden"
    >
      {/* ── Panel header ────────────────────────────────────────────── */}
      <div className="px-8 lg:px-12 pt-10 pb-6 border-b border-ink-3 flex items-end justify-between gap-6 flex-wrap">
        <div>
          <span className="eyebrow">Diagnosis</span>
          <h2 className="mt-2 text-[24px] lg:text-[28px] text-ink-12 tracking-tight">
            Why this score
          </h2>
          <p className="mt-2 text-[13px] text-ink-8 max-w-[52ch]">
            Five dimensions, weighted into the composite. Failure-mode
            labels are decoded through the v1 taxonomy.
          </p>
        </div>
        <AttestationPill attestation={diagnosis.attestation} />
      </div>

      {/* ── Dimension bars ─────────────────────────────────────────── */}
      <div className="px-8 lg:px-12 py-10 border-b border-ink-3">
        <div className="flex items-baseline justify-between mb-6">
          <span className="eyebrow">Dimensions</span>
          <span className="text-[11px] font-mono tracking-eyebrow uppercase text-ink-7">
            score · contribution
          </span>
        </div>
        <div className="space-y-5">
          {diagnosis.dimensions.map((d) => (
            <DimensionBar
              key={d.dimension}
              entry={d}
              contribution={diagnosis.weighted_contributions[d.dimension] ?? 0}
            />
          ))}
        </div>
      </div>

      {/* ── Flag chips ─────────────────────────────────────────────── */}
      <div className="px-8 lg:px-12 py-10 border-b border-ink-3">
        <div className="flex items-baseline justify-between mb-6">
          <span className="eyebrow">Failure modes</span>
          <span className="text-[11px] font-mono tracking-eyebrow uppercase text-ink-7">
            {diagnosis.decoded_labels.length} decoded
            {diagnosis.undecoded_flag_bits.length > 0
              ? ` · ${diagnosis.undecoded_flag_bits.length} trace`
              : ""}
          </span>
        </div>
        {hasFlags ? (
          <div className="space-y-6">
            {SEVERITY_ORDER.map((sev) =>
              grouped[sev].length > 0 ? (
                <SeverityGroup
                  key={sev}
                  severity={sev}
                  labels={grouped[sev]}
                />
              ) : null,
            )}
          </div>
        ) : (
          <EmptyFlags />
        )}
        {diagnosis.undecoded_flag_bits.length > 0 && (
          <TraceBitsLine bits={diagnosis.undecoded_flag_bits} />
        )}
      </div>

      {/* ── Remediation hints ──────────────────────────────────────── */}
      <div className="px-8 lg:px-12 py-10">
        <div className="flex items-baseline justify-between mb-6 gap-4 flex-wrap">
          <div>
            <span className="eyebrow">Suggested remediation</span>
            <p className="mt-2 text-[12px] text-ink-7 max-w-[56ch]">
              Hints — not a verdict. The Phase-2 cert v2 will threshold-sign
              the remediation bitmask itself.
            </p>
          </div>
        </div>
        {diagnosis.remediation_hints.length > 0 ? (
          <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {diagnosis.remediation_hints.slice(0, 8).map((h) => (
              <li
                key={h.bit}
                className={cn(
                  "flex items-center justify-between gap-3 rounded-lg",
                  "border border-ink-3 bg-ink-2 px-3 py-2.5",
                  "text-[13px] text-ink-11 font-mono",
                )}
              >
                <span className="truncate">{h.name}</span>
                <span className="text-[10px] tracking-eyebrow uppercase text-ink-7 shrink-0">
                  bit {h.bit}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[13px] text-ink-8">
            No remediation suggested — diagnosis is clean.
          </p>
        )}
      </div>
    </section>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Dimension bar
// ─────────────────────────────────────────────────────────────────────────────

function DimensionBar({
  entry,
  contribution,
}: {
  entry: DimensionBreakdownEntry;
  contribution: number;
}) {
  const pct = Math.max(0, Math.min(1, entry.score_normalised));
  const meta = DIMENSION_LABELS[entry.dimension] ?? {
    title: entry.dimension,
    blurb: "",
  };
  return (
    <div className="group">
      <div className="flex items-baseline justify-between gap-4 mb-2">
        <div className="flex items-center gap-2">
          <span className="text-[14px] text-ink-12">{meta.title}</span>
          <span
            className="text-ink-7 group-hover:text-ink-10 transition-colors"
            title={meta.blurb}
          >
            <Info size={11} />
          </span>
        </div>
        <div className="flex items-center gap-3 font-mono text-[12px] tabular-nums">
          <span className="text-ink-12">
            {entry.score}
            <span className="text-ink-7"> / {entry.max_score}</span>
          </span>
          <span className="text-ink-7">·</span>
          <span className="text-ink-9">+{contribution}</span>
        </div>
      </div>
      {/* The bar itself — monochrome. Track is ink-3, fill is a stepwise
         opacity ramp on white so it reads as "earned vs unearned" without
         introducing color. */}
      <div className="relative h-1.5 rounded-full bg-ink-3 overflow-hidden">
        <div
          className="absolute inset-y-0 left-0 bg-ink-12/85"
          style={{ width: `${pct * 100}%` }}
          aria-hidden
        />
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Severity grouping + chips
// ─────────────────────────────────────────────────────────────────────────────

function groupBySeverity(
  labels: DecodedFlagLabel[],
): Record<Severity, DecodedFlagLabel[]> {
  const out: Record<Severity, DecodedFlagLabel[]> = {
    CRITICAL: [], HIGH: [], MED: [], LOW: [], INFO: [],
  };
  for (const l of labels) out[l.severity].push(l);
  return out;
}

function SeverityGroup({
  severity,
  labels,
}: {
  severity: Severity;
  labels: DecodedFlagLabel[];
}) {
  return (
    <div>
      <div className="flex items-baseline gap-3 mb-2">
        <span className="text-[11px] font-mono tracking-eyebrow uppercase text-ink-9">
          {severity}
        </span>
        <span className="text-[11px] font-mono text-ink-6">
          {labels.length}
        </span>
      </div>
      <ul className="flex flex-wrap gap-2">
        {labels.map((l) => (
          <FlagChip key={l.bit} label={l} />
        ))}
      </ul>
    </div>
  );
}

function FlagChip({ label }: { label: DecodedFlagLabel }) {
  const owasp = label.owasp_refs.join(" · ");
  const tooltip = owasp
    ? `${label.description}\n\nOWASP: ${owasp}\nbit ${label.bit}`
    : `${label.description}\n\nbit ${label.bit}`;
  return (
    <li>
      <span
        title={tooltip}
        className={cn(
          "inline-flex items-center gap-2 rounded-full border px-3 py-1",
          "font-mono text-[11px] tracking-tight",
          severityClass(label.severity),
        )}
      >
        <span className="truncate max-w-[28ch]">{label.name}</span>
        {label.owasp_refs.length > 0 && (
          <span className="text-[10px] opacity-70">
            {label.owasp_refs[0]}
          </span>
        )}
      </span>
    </li>
  );
}

function EmptyFlags() {
  return (
    <div className="rounded-xl border border-ink-3 bg-ink-2 px-5 py-6 text-center">
      <p className="text-[13px] text-ink-9">
        No failure modes decoded for this epoch.
      </p>
      <p className="mt-1 text-[12px] text-ink-7">
        The detectors fired cleanly; the score reflects baseline behaviour.
      </p>
    </div>
  );
}

function TraceBitsLine({ bits }: { bits: number[] }) {
  return (
    <p className="mt-6 text-[11px] font-mono text-ink-7">
      Trace bits set: {bits.map((b) => `bit ${b}`).join(" · ")} — legacy
      detector bits not modelled by the v1 diagnosis taxonomy.
    </p>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Attestation pill — surfaces the Phase-1 / Phase-2 honesty
// ─────────────────────────────────────────────────────────────────────────────

function AttestationPill({ attestation }: { attestation: string }) {
  return (
    <span
      title={
        attestation === "off_chain_v1"
          ? "Phase-1: faithful to the oracle's epoch_runner output but not yet threshold-signed. Phase-2 (cert v2) carries the same shape on-chain."
          : "Phase-2: threshold-signed by the cluster."
      }
      className={cn(
        "inline-flex items-center gap-2 rounded-full border border-ink-4",
        "bg-ink-2 px-3 py-1 font-mono text-[11px] tracking-eyebrow uppercase",
        "text-ink-9",
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-ink-7" />
      Attestation · {attestation}
    </span>
  );
}
