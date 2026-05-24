import Link from "next/link";
import { cn } from "@/lib/cn";
import { truncateWallet } from "@/lib/format";
import { RECENT_TICKER_ITEMS } from "@/lib/mock";

/**
 * MarqueeTicker — the live "what's been scored" feed across the bottom of
 * the hero. Pure CSS marquee animation, duplicated content for seamless
 * loop. Pauses on hover so a curious partner can read.
 *
 * Each item is a *link* to the agent page — the marquee isn't decoration,
 * it's a navigation surface that doubles as "this protocol is producing
 * real certs right now."
 */
export function MarqueeTicker() {
  const items = [...RECENT_TICKER_ITEMS, ...RECENT_TICKER_ITEMS, ...RECENT_TICKER_ITEMS];

  return (
    <div className="relative overflow-hidden border-y border-ink-3 bg-ink-1 group">
      <div className="absolute left-0 top-0 bottom-0 w-32 z-10 pointer-events-none bg-gradient-to-r from-ink-1 to-transparent" />
      <div className="absolute right-0 top-0 bottom-0 w-32 z-10 pointer-events-none bg-gradient-to-l from-ink-1 to-transparent" />

      <div className="flex items-center py-3 marquee-track group-hover:[animation-play-state:paused]">
        {items.map((item, i) => (
          <Link
            key={`${item.wallet}-${i}`}
            href={`/agent/${item.wallet}`}
            className={cn(
              "shrink-0 flex items-center gap-3 px-6",
              "border-r border-ink-3",
              "group/item",
            )}
          >
            <span className={cn("h-1.5 w-1.5 rounded-full", {
              "bg-tier-green":  item.tier === "GREEN",
              "bg-tier-yellow": item.tier === "YELLOW",
              "bg-tier-red":    item.tier === "RED",
            })} />
            <span className="font-mono text-[11px] tracking-eyebrow uppercase text-ink-7">
              {item.label}
            </span>
            <span className="font-mono text-[11px] text-ink-7">
              {truncateWallet(item.wallet, 4, 4)}
            </span>
            <span className="font-mono text-[13px] text-ink-12 group-hover/item:text-ink-12">
              {item.score}
            </span>
          </Link>
        ))}
      </div>
    </div>
  );
}
