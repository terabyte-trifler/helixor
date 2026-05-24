import { ArrowUpRight } from "lucide-react";
import { getByzantineRecent, getStrikeSummary } from "@/lib/api";
import { truncateWallet } from "@/lib/format";
import { cn } from "@/lib/cn";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Transparency",
  description: "Every Byzantine flag, every challenge, every slashing.",
};

export default async function TransparencyPage() {
  const [byz, strikes] = await Promise.all([
    getByzantineRecent(),
    getStrikeSummary(),
  ]);

  const strikeRows = Object.entries(strikes.summary);

  return (
    <div className="mx-auto max-w-5xl px-6 lg:px-10 py-16 lg:py-24">
      <span className="eyebrow">Transparency</span>
      <h1 className="mt-4 text-display-1 text-ink-12 tracking-tight max-w-[16ch]">
        Every flag. Every challenge.
      </h1>
      <p className="mt-6 max-w-[600px] text-[16px] text-ink-9 leading-relaxed">
        Helixor publishes every Byzantine detection event and every
        on-chain challenge to the public registry. Nothing is filed
        privately. Nothing is reviewed behind closed doors. The on-chain
        record is the only record.
      </p>

      <section className="mt-16">
        <span className="eyebrow">Strikes against cluster nodes</span>
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

      <section className="mt-20">
        <span className="eyebrow">Detection events</span>
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
                    className="inline-flex items-center gap-1 text-[12px] text-chain hover:underline shrink-0"
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
