import type { Metadata } from "next";
import { cn } from "@/lib/cn";
import {
  TAXONOMY,
  highBitModes,
  lowBitModes,
  severityClass,
  type FailureModeEntry,
  type RemediationEntry,
} from "@/lib/taxonomy";
import type { Severity } from "@/types/api";

export const metadata: Metadata = {
  title: "Taxonomy · v1",
  description:
    "The Helixor diagnosis taxonomy: every failure-mode bit, severity, OWASP reference, and remediation code. The bit layout is frozen by pin tests in helixor-oracle/tests/diagnosis.",
};

const SEVERITY_LEGEND: Array<[Severity, string]> = [
  ["CRITICAL", "Pause and isolate. Threshold-signed evidence required."],
  ["HIGH", "Operator review within the same epoch."],
  ["MED", "Auditor review across the next handful of epochs."],
  ["LOW", "Tracked. Suggested fix is mechanical, not adversarial."],
  ["INFO", "Diagnostic context only — no action by default."],
];

export default function TaxonomyPage() {
  const high = highBitModes();
  const low = lowBitModes();
  const remediations = TAXONOMY.remediation_codes;

  return (
    <div className="mx-auto max-w-5xl px-6 lg:px-10 py-16 lg:py-24">
      <span className="eyebrow">Standards</span>
      <h1 className="mt-4 text-display-1 text-ink-12 tracking-tight max-w-[16ch]">
        Diagnosis taxonomy v1.
      </h1>
      <p className="mt-6 max-w-[640px] text-[16px] text-ink-9 leading-relaxed">
        Every failure mode Helixor can attest to lives in this table.
        Each entry is a fixed bit position, an English description, a
        severity, and the OWASP references that anchor the label to the
        wider AI-security literature. The bit layout is frozen — pin
        tests in <code className="font-mono text-[13px] text-ink-11">helixor-oracle/tests/diagnosis</code>{" "}
        treat any drift as a breaking on-chain change.
      </p>

      <p className="mt-4 max-w-[640px] text-[13px] text-ink-7 leading-relaxed">
        Schema version <span className="font-mono text-ink-9">v{TAXONOMY.schema_version}</span>{" "}
        · {TAXONOMY.failure_modes.length} failure modes ·{" "}
        {remediations.length} remediation codes.
      </p>

      {/* ── Severity legend ─────────────────────────────────────────── */}
      <section className="mt-12">
        <span className="eyebrow">Severity</span>
        <h2 className="mt-2 text-[22px] text-ink-12 tracking-tight">
          What each level means
        </h2>
        <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {SEVERITY_LEGEND.map(([sev, blurb]) => (
            <div
              key={sev}
              className={cn(
                "rounded-xl border bg-ink-1 px-4 py-3",
                severityClass(sev).split(" ").find((c) => c.startsWith("border-")) ??
                  "border-ink-3",
              )}
            >
              <div
                className={cn(
                  "font-mono text-[11px] tracking-eyebrow uppercase",
                  severityClass(sev).split(" ").find((c) => c.startsWith("text-")) ??
                    "text-ink-11",
                )}
              >
                {sev}
              </div>
              <div className="mt-2 text-[12px] text-ink-9 leading-relaxed">
                {blurb}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Diagnosis labels (high-32 bits) ─────────────────────────── */}
      <section className="mt-16">
        <span className="eyebrow">v1 diagnosis labels</span>
        <h2 className="mt-2 text-[22px] text-ink-12 tracking-tight">
          High-32 bits · OWASP-aligned
        </h2>
        <p className="mt-3 max-w-[620px] text-[13px] text-ink-8 leading-relaxed">
          These are the authoritative diagnosis labels. The Phase-2 cert
          v2 will threshold-sign these bits; consumers should branch on
          them, not on the legacy detector trace bits below.
        </p>
        <div className="mt-6 rounded-2xl border border-ink-3 bg-ink-1 overflow-hidden">
          {high.map((m, i) => (
            <FailureModeRow
              key={m.bit}
              entry={m}
              divider={i !== high.length - 1}
            />
          ))}
        </div>
      </section>

      {/* ── Trace bits (low-32) ─────────────────────────────────────── */}
      <section className="mt-16">
        <span className="eyebrow">Legacy trace bits</span>
        <h2 className="mt-2 text-[22px] text-ink-12 tracking-tight">
          Low-32 bits · detector trace
        </h2>
        <div className="mt-4 rounded-xl border border-ink-3 bg-ink-2 px-5 py-4">
          <p className="text-[13px] text-ink-10 leading-relaxed">
            <span className="font-mono text-ink-12">D2 honesty note —</span>{" "}
            the low-32 bits are passthrough trace bits from the legacy
            detector bitset. They explain WHY a score is low but are NOT
            full taxonomy entries. They share the bitmask only because
            the on-chain field was reserved as <code className="font-mono">u64</code>{" "}
            and the upper 32 bits hold the v1 diagnosis surface. A
            consumer building an audit pipeline should switch on the
            high-32 labels — the low-32 set is informational.
          </p>
        </div>
        <div className="mt-6 rounded-2xl border border-ink-3 bg-ink-1 overflow-hidden">
          {low.map((m, i) => (
            <FailureModeRow
              key={m.bit}
              entry={m}
              divider={i !== low.length - 1}
            />
          ))}
        </div>
      </section>

      {/* ── Remediation codes ───────────────────────────────────────── */}
      <section className="mt-16">
        <span className="eyebrow">Remediation</span>
        <h2 className="mt-2 text-[22px] text-ink-12 tracking-tight">
          Actionable codes · u32 bitmask
        </h2>
        <p className="mt-3 max-w-[620px] text-[13px] text-ink-8 leading-relaxed">
          Every failure mode declares a default-remediation bitmask. The
          codes below are the bit-by-bit playbook the cluster surfaces
          alongside the diagnosis.
        </p>
        <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 gap-2">
          {remediations.map((r) => (
            <RemediationRow key={r.bit} entry={r} />
          ))}
        </div>
      </section>

      {/* ── Footnote on attestation ─────────────────────────────────── */}
      <section className="mt-20 pt-12 border-t border-ink-3">
        <span className="eyebrow">Attestation tiers</span>
        <h2 className="mt-2 text-[22px] text-ink-12 tracking-tight">
          off_chain_v1 → cert_v2
        </h2>
        <p className="mt-3 max-w-[640px] text-[13px] text-ink-9 leading-relaxed">
          Phase-1 (today) serves the diagnosis off-chain with the
          attestation tag <code className="font-mono text-ink-11">off_chain_v1</code>.
          The data is faithful to the cluster's epoch_runner output but is
          NOT yet threshold-signed. Phase-2 lifts the same shape into
          cert v2 with the tag <code className="font-mono text-ink-11">cert_v2</code>.
          The wire contract is explicit so a downstream auditor can
          branch on the literal.
        </p>
      </section>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────

function FailureModeRow({
  entry,
  divider,
}: {
  entry: FailureModeEntry;
  divider: boolean;
}) {
  return (
    <div
      className={cn(
        "px-6 py-5 grid grid-cols-12 gap-4 items-baseline",
        divider && "border-b border-ink-3",
      )}
    >
      <div className="col-span-12 sm:col-span-4 flex items-center gap-3 flex-wrap">
        <span className="font-mono text-[13px] text-ink-12 break-all">
          {entry.name}
        </span>
        <span
          className={cn(
            "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5",
            "font-mono text-[10px] tracking-eyebrow uppercase",
            severityClass(entry.severity),
          )}
        >
          {entry.severity}
        </span>
      </div>
      <div className="col-span-12 sm:col-span-6 text-[13px] text-ink-10 leading-relaxed">
        {entry.description}
        {entry.owasp_refs.length > 0 && (
          <div className="mt-1.5 flex flex-wrap gap-2">
            {entry.owasp_refs.map((ref) => (
              <span
                key={ref}
                className="font-mono text-[10px] tracking-eyebrow uppercase text-ink-7"
              >
                {ref}
              </span>
            ))}
          </div>
        )}
      </div>
      <div className="col-span-12 sm:col-span-2 sm:text-right font-mono text-[11px] tracking-eyebrow uppercase text-ink-7">
        bit {entry.bit}
      </div>
    </div>
  );
}

function RemediationRow({ entry }: { entry: RemediationEntry }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border border-ink-3 bg-ink-1 px-4 py-3">
      <span className="font-mono text-[13px] text-ink-11 truncate">
        {entry.name}
      </span>
      <span className="font-mono text-[10px] tracking-eyebrow uppercase text-ink-7 shrink-0">
        bit {entry.bit}
      </span>
    </div>
  );
}
