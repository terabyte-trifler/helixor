import { cn } from "@/lib/cn";
import type { AlertTier } from "@/types/api";

const TIER_STYLES: Record<AlertTier, string> = {
  GREEN:  "text-tier-green border-tier-green/30 bg-tier-green/[0.08]",
  YELLOW: "text-tier-yellow border-tier-yellow/30 bg-tier-yellow/[0.08]",
  RED:    "text-tier-red border-tier-red/40 bg-tier-red/[0.10]",
};

/**
 * Tier badge — a pill. Small, all-caps, mono, with the tier's color
 * applied to text + border + faint background tint. The faint tint is
 * essential: pure text color on black looks unfinished; the tint makes
 * it feel like a deliberate UI element.
 */
export function TierBadge({
  tier,
  immediateRed,
  size = "md",
}: {
  tier: AlertTier;
  immediateRed?: boolean;
  size?: "sm" | "md";
}) {
  const label = immediateRed ? "IMMEDIATE RED" : tier;
  const sizing =
    size === "sm"
      ? "h-5 px-2 text-[10px]"
      : "h-6 px-2.5 text-[11px]";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border",
        "font-mono tracking-eyebrow font-medium",
        sizing,
        TIER_STYLES[tier],
      )}
    >
      <span className={cn("h-1 w-1 rounded-full", {
        "bg-tier-green":  tier === "GREEN",
        "bg-tier-yellow": tier === "YELLOW",
        "bg-tier-red":    tier === "RED",
      })} />
      {label}
    </span>
  );
}
