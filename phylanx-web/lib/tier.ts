/**
 * lib/tier.ts — alert tier helpers.
 *
 * The three tiers (GREEN/YELLOW/RED) are the ONLY colored elements in the
 * site outside of the explorer-link blue and the cluster-heartbeat green.
 * Centralised so a future tier rename or color change is one edit.
 */

import type { AlertTier } from "@/types/api";

export const TIER_COLORS: Record<AlertTier, string> = {
  GREEN:  "#34d399",
  YELLOW: "#fbbf24",
  RED:    "#f87171",
};

export const TIER_RING_CLASS: Record<AlertTier, string> = {
  GREEN:  "stroke-tier-green",
  YELLOW: "stroke-tier-yellow",
  RED:    "stroke-tier-red",
};

export const TIER_TEXT_CLASS: Record<AlertTier, string> = {
  GREEN:  "text-tier-green",
  YELLOW: "text-tier-yellow",
  RED:    "text-tier-red",
};

export const TIER_BG_DOT_CLASS: Record<AlertTier, string> = {
  GREEN:  "bg-tier-green",
  YELLOW: "bg-tier-yellow",
  RED:    "bg-tier-red",
};

export function tierLabel(t: AlertTier, immediateRed: boolean): string {
  if (immediateRed) return "IMMEDIATE RED";
  return t;
}
