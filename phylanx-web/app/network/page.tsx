import { Pill } from "@/components/ui/Pill";
import { Radio, Server, History as HistoryIcon, ShieldAlert } from "lucide-react";
import { ArrowUpRight, Check } from "lucide-react";
import { getClusterHealth, getByzantineRecent, getStrikeSummary, getVersion } from "@/lib/api";
import { formatAbsoluteUTC, formatRelative, truncateWallet } from "@/lib/format";
import { cn } from "@/lib/cn";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Network",
  description: "Live status of the Phylanx BFT oracle cluster.",
  alternates: { canonical: "/network" },
};

export default async function NetworkPage() {
  const [cluster, byz, strikes, version] = await Promise.all([
    getClusterHealth(),
    getByzantineRecent(),
    getStrikeSummary(),
    getVersion(),
  ]);

  const now = Date.now() / 1000;
  const nodesOnline = cluster.heartbeats.filter(
    (h) => now - h.last_seen_unix < 120,
  ).length;

  return (
    <div className="mx-auto max-w-7xl px-6 lg:px-10 py-16 lg:py-24">
      {/* ── Header ────────────────────────────────────────────────────── */}
      <div>
        <Pill icon={<Radio size={11} strokeWidth={2.5} />}>Network status</Pill>
        <h1 className="mt-4 text-display-1 text-ink-12 tracking-tight">
          The cluster, <br />
          <span className="text-ink-8">in plain sight.</span>
        </h1>
        <p className="mt-6 max-w-[560px] text-[16px] text-ink-9 leading-relaxed">
          Phylanx publishes everything: every node, every epoch, every
          Byzantine flag, every challenge. The same data the runbooks
          read at 3am.
        </p>
      </div>

      {/* ── Top stats ─────────────────────────────────────────────────── */}
      <div className="mt-14 grid grid-cols-2 md:grid-cols-4 gap-px bg-ink-3 border border-ink-3 rounded-2xl overflow-hidden">
        <BigStat label="Nodes online" value={`${nodesOnline} / 5`} />
        <BigStat label="Threshold" value="3 of 5" />
        <BigStat label="Current epoch" value={`${cluster.recent_epochs[0]?.epoch ?? "—"}`} />
        <BigStat
          label="Mean epoch latency"
          value={
            cluster.recent_epochs.length
              ? `${(cluster.recent_epochs.reduce((s, e) => s + e.elapsed_seconds, 0)
                  / cluster.recent_epochs.length).toFixed(1)}s`
              : "—"
          }
        />
      </div>

      {/* ── Nodes ─────────────────────────────────────────────────────── */}
      <section className="mt-20">
        <div className="flex items-end justify-between mb-6">
          <div>
            <Pill icon={<Server size={11} strokeWidth={2.5} />}>Nodes</Pill>
            <h2 className="mt-2 text-[24px] text-ink-12 tracking-tight">
              5 independent oracle nodes
            </h2>
          </div>
          <span className="text-[12px] font-mono text-ink-7">
            ed25519 · {version.network}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-px bg-ink-3 border border-ink-3 rounded-2xl overflow-hidden">
          {cluster.heartbeats.map((h) => {
            const ago = now - h.last_seen_unix;
            const live = ago < 120;
            const strikeRow = strikes.summary[h.node];
            return (
              <div key={h.node} className="bg-ink-1 p-6">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[12px] text-ink-7 tracking-eyebrow uppercase">
                    {h.node.replace("oracle-node-", "node ")}
                  </span>
                  <span
                    className={cn(
                      "inline-flex items-center gap-1.5 text-[11px] font-mono",
                      live ? "text-ok" : "text-tier-yellow",
                    )}
                  >
                    <span
                      className={cn(
                        "h-1.5 w-1.5 rounded-full",
                        live ? "bg-ok animate-heartbeat" : "bg-tier-yellow",
                      )}
                    />
                    {live ? "live" : "stale"}
                  </span>
                </div>
                <div className="mt-6 space-y-3">
                  <NodeRow label="Last seen" value={`${Math.floor(ago)}s ago`} />
                  <NodeRow label="Epoch" value={`${h.epoch}`} />
                  <NodeRow
                    label="Strikes"
                    value={
                      strikeRow ? (
                        <span className="text-tier-yellow">
                          {strikeRow.strikes} / 3
                        </span>
                      ) : (
                        <span className="text-ok inline-flex items-center gap-1">
                          <Check size={11} strokeWidth={2.5} /> 0
                        </span>
                      )
                    }
                  />
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* ── Recent epochs ─────────────────────────────────────────────── */}
      <section className="mt-20">
        <div className="flex items-end justify-between mb-6">
          <Pill icon={<HistoryIcon size={11} strokeWidth={2.5} />}>Last 10 epochs</Pill>
          <span className="text-[12px] font-mono text-ink-7">
            chronological, newest first
          </span>
        </div>
        <div className="rounded-2xl border border-ink-3 bg-ink-1 overflow-hidden">
          <div className="grid grid-cols-12 gap-4 px-6 py-3 border-b border-ink-3 bg-ink-2 text-[10px] font-mono tracking-eyebrow uppercase text-ink-7">
            <div className="col-span-1">Epoch</div>
            <div className="col-span-2">Submitted</div>
            <div className="col-span-2">Verified</div>
            <div className="col-span-2">Byzantine</div>
            <div className="col-span-2">Unreachable</div>
            <div className="col-span-2">Latency</div>
            <div className="col-span-1 text-right">Time</div>
          </div>
          {cluster.recent_epochs.map((e, i) => (
            <div
              key={e.epoch}
              className={cn(
                "grid grid-cols-12 gap-4 items-center px-6 py-3.5 text-[13px]",
                i !== cluster.recent_epochs.length - 1 && "border-b border-ink-3",
              )}
            >
              <div className="col-span-1 font-mono text-ink-12">{e.epoch}</div>
              <div className="col-span-2 font-mono">
                <span className="text-ink-12">{e.submitted_count}</span>
                <span className="text-ink-7"> / {e.agent_count}</span>
              </div>
              <div className="col-span-2 font-mono text-ink-9">
                {e.verified_nodes.length}
              </div>
              <div className="col-span-2 font-mono">
                {e.byzantine_nodes.length === 0 ? (
                  <span className="text-ink-7">—</span>
                ) : (
                  <span className="text-tier-yellow">
                    {e.byzantine_nodes.length}
                  </span>
                )}
              </div>
              <div className="col-span-2 font-mono">
                {e.unreachable_nodes.length === 0 ? (
                  <span className="text-ink-7">—</span>
                ) : (
                  <span className="text-tier-yellow">
                    {e.unreachable_nodes.length}
                  </span>
                )}
              </div>
              <div className="col-span-2 font-mono text-ink-9 tabular-nums">
                {e.elapsed_seconds.toFixed(2)}s
              </div>
              <div className="col-span-1 text-right text-ink-7 text-[12px]">
                {formatRelative(e.computed_at)}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Byzantine activity ────────────────────────────────────────── */}
      <section className="mt-20">
        <div className="flex items-end justify-between mb-6">
          <div>
            <Pill icon={<ShieldAlert size={11} strokeWidth={2.5} />}>Watchdog activity</Pill>
            <h2 className="mt-2 text-[24px] text-ink-12 tracking-tight">
              Byzantine flags · last 30 days
            </h2>
          </div>
        </div>
        {byz.flags.length === 0 ? (
          <div className="rounded-2xl border border-ink-3 bg-ink-1 p-12 text-center">
            <p className="text-[14px] text-ink-9">
              No flags in the period. The cluster has been deterministic
              across every honest node.
            </p>
          </div>
        ) : (
          <div className="rounded-2xl border border-ink-3 bg-ink-1 overflow-hidden">
            {byz.flags.map((f, i) => (
              <div
                key={`${f.node}-${f.epoch}`}
                className={cn(
                  "px-6 py-5",
                  i !== byz.flags.length - 1 && "border-b border-ink-3",
                )}
              >
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div>
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-[14px] text-tier-yellow">
                        {f.node}
                      </span>
                      <span className="text-ink-7 text-[12px]">flagged on</span>
                      <span className="font-mono text-[14px] text-ink-12">
                        epoch {f.epoch}
                      </span>
                    </div>
                    <p className="mt-1.5 text-[13px] text-ink-9">
                      Reported{" "}
                      <span className="font-mono text-ink-12 tabular-nums">
                        {f.accused_score}
                      </span>{" "}
                      against cluster median{" "}
                      <span className="font-mono text-ink-12 tabular-nums">
                        {f.cluster_median}
                      </span>{" "}
                      ({(f.deviation * 100).toFixed(1)}% deviation) for{" "}
                      <span className="font-mono text-ink-10">
                        {truncateWallet(f.subject_agent, 4, 4)}
                      </span>
                    </p>
                  </div>
                  <a
                    href="#"
                    className="inline-flex items-center gap-1 text-[12px] text-accent hover:underline"
                  >
                    on-chain proof <ArrowUpRight size={11} />
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* ── Version footer ────────────────────────────────────────────── */}
      <section className="mt-20 pt-10 border-t border-ink-3">
        <div className="flex flex-wrap items-center gap-x-8 gap-y-3 text-[12px] font-mono text-ink-7">
          <span>api {version.api_version}</span>
          <span className="text-ink-5">·</span>
          <span>scoring {version.scoring_algo_version}</span>
          <span className="text-ink-5">·</span>
          <span>weights {version.scoring_weights_version}</span>
          <span className="text-ink-5">·</span>
          <span>network {version.network}</span>
          <span className="text-ink-5">·</span>
          <span>cluster computed at {formatAbsoluteUTC(cluster.recent_epochs[0]?.computed_at ?? new Date().toISOString())}</span>
        </div>
      </section>
    </div>
  );
}

function BigStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-ink-1 p-8">
      <div className="eyebrow-accent">{label}</div>
      <div className="mt-3 font-mono text-display-3 text-ink-12 tabular-nums">
        {value}
      </div>
    </div>
  );
}

function NodeRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between text-[12px]">
      <span className="text-ink-7">{label}</span>
      <span className="font-mono text-ink-12 tabular-nums">{value}</span>
    </div>
  );
}
