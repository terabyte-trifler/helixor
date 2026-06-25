import { ArrowUpRight, Eye, AlertTriangle, Flag } from "lucide-react";
import { getByzantineRecent, getLabelDeviations, getStrikeSummary } from "@/lib/api";
import { truncateWallet } from "@/lib/format";
import { cn } from "@/lib/cn";
import { failureModeByBit, severityClass } from "@/lib/taxonomy";
import { Pill } from "@/components/ui/Pill";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Transparency",
  description: "Every Byzantine flag, every challenge, every slashing.",
  alternates: { canonical: "/transparency" },
};

export default async function TransparencyPage() {
  const [byz, strikes, labelDeviations] = await Promise.all([
    getByzantineRecent(),
    getStrikeSummary(),
    getLabelDeviations(),
  ]);

  const strikeRows = Object.entries(strikes.summary);

  return (
    <div className="mx-auto max-w-5xl px-6 lg:px-10 py-16 lg:py-24">
      <Pill icon={<Eye size={11} strokeWidth={2.5} />}>Transparency</Pill>
      <h1 className="mt-4 text-display-1 text-ink-12 tracking-tight max-w-[16ch]">
        Every flag. Every challenge.
      </h1>
      <p className="mt-6 max-w-[600px] text-[16px] text-ink-9 leading-relaxed">
        Phylanx publishes every Byzantine detection event and every
        on-chain challenge to the public registry. Nothing is filed
        privately. Nothing is reviewed behind closed doors. The on-chain
        record is the only record.
      </p>

      <section className="mt-16">
        <Pill icon={<AlertTriangle size={11} strokeWidth={2.5} />}>Strikes against cluster nodes</Pill>
        <h2 className="mt-2 text-[22px] text-ink-12 tracking-tight">
          Live strike counter
        </h2>
        <div className="mt-6 rounded-2xl border border-ink-3 bg-ink-1 overflow-hidden">
          {strikeRows.length === 0 ? (
            <div className="p-12 text-center text-[14px] text-ink-9">
              No strikes against any node. The cluster has been
              deterministic across all honest signers.
            </div>
          ) : (
            strikeRows.map(([node, entry], i) => (
              <div
                key={node}
                className={cn(
                  "px-6 py-5 flex items-center justify-between flex-wrap gap-3",
                  i !== strikeRows.length - 1 && "border-b border-ink-3",
                )}
              >
                <div>
                  <div className="font-mono text-[14px] text-ink-12">{node}</div>
                  <div className="mt-1 text-[12px] text-ink-9">
                    {entry.flagged_epochs.length} flagged epoch
                    {entry.flagged_epochs.length === 1 ? "" : "s"}:{" "}
                    {entry.flagged_epochs.join(", ")}
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span
                    className={cn(
                      "font-mono text-[11px] tracking-eyebrow uppercase",
                      entry.challenged
                        ? "text-tier-red"
                        : entry.strikes >= 2
                        ? "text-tier-yellow"
                        : "text-ink-9",
                    )}
                  >
                    {entry.challenged
                      ? "challenged"
                      : `${entry.strikes} / 3 strikes`}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      {/* Day-41: label-deviation events. Score-level disagreement is
          published above; this surface shows which oracle disagreed on
          which LABELS, for which agent, in which epoch. */}
      <section className="mt-20">
        <Pill icon={<AlertTriangle size={11} strokeWidth={2.5} />}>Label-level disagreement</Pill>
        <h2 className="mt-2 text-[22px] text-ink-12 tracking-tight">
          Where the cluster split on the diagnosis
        </h2>
        <p className="mt-2 text-[13px] text-ink-8 max-w-[60ch]">
          A node may agree on the score but miss a label, or call a
          label the rest of the cluster dropped. Either way it&apos;s
          public.
        </p>
        <div className="mt-6 rounded-2xl border border-ink-3 bg-ink-1 overflow-hidden">
          {labelDeviations.length === 0 ? (
            <div className="p-12 text-center text-[14px] text-ink-9">
              No label deviations recorded in the current window.
            </div>
          ) : (
            labelDeviations.map((ev, i) => {
              const missed = ev.majority_bits.filter(
                (b) => !ev.minority_bits.includes(b),
              );
              const overcalled = ev.minority_bits.filter(
                (b) => !ev.majority_bits.includes(b),
              );
              return (
                <div
                  key={`${ev.node}-${ev.epoch}-${i}`}
                  className={cn(
                    "p-6",
                    i !== labelDeviations.length - 1 && "border-b border-ink-3",
                  )}
                >
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="font-mono text-[14px] text-tier-yellow">
                      {ev.node}
                    </span>
                    <span className="text-[12px] text-ink-7">
                      diverged on
                    </span>
                    <span className="font-mono text-[14px] text-ink-12">
                      epoch {ev.epoch}
                    </span>
                    <span className="text-[12px] text-ink-7">·</span>
                    <span className="text-[12px] text-ink-9">
                      agent{" "}
                      <span className="font-mono text-ink-10">
                        {truncateWallet(ev.subject_agent, 6, 6)}
                      </span>
                    </span>
                  </div>
                  {missed.length > 0 && (
                    <DeviationRow
                      kind="missed"
                      bits={missed}
                      blurb="cluster called, this node missed"
                    />
                  )}
                  {overcalled.length > 0 && (
                    <DeviationRow
                      kind="overcalled"
                      bits={overcalled}
                      blurb="this node called, cluster dropped"
                    />
                  )}
                </div>
              );
            })
          )}
        </div>
      </section>

      <section className="mt-20">
        <Pill icon={<Flag size={11} strokeWidth={2.5} />}>Detection events</Pill>
        <h2 className="mt-2 text-[22px] text-ink-12 tracking-tight">
          Byzantine flags this period
        </h2>
        <div className="mt-6 rounded-2xl border border-ink-3 bg-ink-1 overflow-hidden">
          {byz.flags.length === 0 ? (
            <div className="p-12 text-center text-[14px] text-ink-9">
              No flags fired in the current window.
            </div>
          ) : (
            byz.flags.map((f, i) => (
              <div
                key={`${f.node}-${f.epoch}`}
                className={cn(
                  "p-6",
                  i !== byz.flags.length - 1 && "border-b border-ink-3",
                )}
              >
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div>
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className="font-mono text-[14px] text-tier-yellow">
                        {f.node}
                      </span>
                      <span className="text-[12px] text-ink-7">flagged on</span>
                      <span className="font-mono text-[14px] text-ink-12">
                        epoch {f.epoch}
                      </span>
                    </div>
                    <p className="mt-2 text-[13px] text-ink-9">
                      reported{" "}
                      <span className="font-mono text-ink-12 tabular-nums">
                        {f.accused_score}
                      </span>{" "}
                      against cluster median{" "}
                      <span className="font-mono text-ink-12 tabular-nums">
                        {f.cluster_median}
                      </span>{" "}
                      —{" "}
                      <span className="text-ink-12 font-medium">
                        {(f.deviation * 100).toFixed(1)}% deviation
                      </span>{" "}
                      on agent{" "}
                      <span className="font-mono text-ink-10">
                        {truncateWallet(f.subject_agent, 6, 6)}
                      </span>
                    </p>
                  </div>
                  <a
                    href="#"
                    className="inline-flex items-center gap-1 text-[12px] text-accent hover:underline shrink-0"
                  >
                    on-chain proof <ArrowUpRight size={11} />
                  </a>
                </div>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}

function DeviationRow({
  kind,
  bits,
  blurb,
}: {
  kind: "missed" | "overcalled";
  bits: number[];
  blurb: string;
}) {
  return (
    <div className="mt-3">
      <span className="font-mono text-[10px] tracking-eyebrow uppercase text-ink-7">
        {blurb}
      </span>
      <ul className="mt-2 flex flex-wrap gap-2">
        {bits.map((bit) => {
          const mode = failureModeByBit(bit);
          const label = mode?.name ?? `bit ${bit}`;
          return (
            <li key={bit}>
              <span
                className={cn(
                  "inline-flex items-center gap-2 rounded-full border px-2.5 py-1",
                  "font-mono text-[11px]",
                  mode
                    ? severityClass(mode.severity)
                    : "text-ink-9 border-ink-4 bg-ink-2",
                )}
                title={mode?.description ?? `bit ${bit}`}
              >
                <span>{label}</span>
                <span className="text-[10px] opacity-70">
                  {kind === "missed" ? "−" : "+"}
                </span>
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
