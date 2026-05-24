/**
 * lib/mock.ts — deterministic mock data.
 *
 * Same shape as helixor-api/api/schemas.py — every response carries _v: 1
 * and matches the Pydantic models field for field. The mock layer is what
 * makes the YC demo work BEFORE the devnet API is deployed.
 *
 * Determinism: every "random" value is keyed off the agent wallet via a
 * tiny hash so the same wallet always gets the same score on every
 * render. This is critical for the demo — a partner pastes a wallet,
 * shares the URL, and the same score loads on the other end.
 */

import type {
  ByzantineRecentResponse,
  ChallengesResponse,
  ClusterHealthResponse,
  HealthResponse,
  HistoryResponse,
  StrikeSummaryResponse,
  VersionResponse,
} from "@/types/api";

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic hash → 0..1 for use as a seed
// ─────────────────────────────────────────────────────────────────────────────

function hash01(s: string): number {
  // FNV-1a, fine for non-cryptographic determinism.
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0) / 0xffffffff;
}

function range(seed: number, min: number, max: number): number {
  return min + seed * (max - min);
}

// ─────────────────────────────────────────────────────────────────────────────
// Featured demo agents — these are the ones the landing page shows in the
// "What's been scored" ticker, the "examples to try" list. Each gets a
// hand-tuned story so the demo doesn't feel uniform.
// ─────────────────────────────────────────────────────────────────────────────

interface FeaturedAgent {
  wallet: string;
  label: string;
  score: number;
  tier: "GREEN" | "YELLOW" | "RED";
  story: string;
}

export const FEATURED_AGENTS: FeaturedAgent[] = [
  {
    wallet: "Hxr1Demo01StableTrader1111111111111111111111",
    label: "Stable arb bot",
    score: 941,
    tier: "GREEN",
    story: "Consistent 18-month track record. Predictable inflows.",
  },
  {
    wallet: "Hxr2Demo02RecoveringYieldAgent11111111111111",
    label: "Yield agent (recovering)",
    score: 712,
    tier: "YELLOW",
    story: "Two flagged epochs in April; baseline rebuilt since.",
  },
  {
    wallet: "Hxr3Demo03DriftingMarketMaker111111111111111",
    label: "MM strategy (drift)",
    score: 583,
    tier: "YELLOW",
    story: "Behavior shifted last week. Watch list.",
  },
  {
    wallet: "Hxr4Demo04FlaggedExfilAgent1111111111111111x",
    label: "Compromised agent",
    score: 184,
    tier: "RED",
    story: "Caught attempting exfiltration. Immediate-red fired.",
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Score generation
// ─────────────────────────────────────────────────────────────────────────────

function tierFromScore(score: number): {
  tier: "GREEN" | "YELLOW" | "RED";
  code: 0 | 1 | 2;
} {
  if (score >= 800) return { tier: "GREEN", code: 0 };
  if (score >= 400) return { tier: "YELLOW", code: 1 };
  return { tier: "RED", code: 2 };
}

function syntheticScore(wallet: string): {
  score: number;
  tier: "GREEN" | "YELLOW" | "RED";
  code: 0 | 1 | 2;
  immediate_red: boolean;
} {
  // Featured agents have hand-tuned scores.
  const featured = FEATURED_AGENTS.find((a) => a.wallet === wallet);
  if (featured) {
    return {
      score: featured.score,
      tier: featured.tier,
      code: featured.tier === "GREEN" ? 0 : featured.tier === "YELLOW" ? 1 : 2,
      immediate_red: featured.tier === "RED",
    };
  }
  // Otherwise, deterministic from the wallet. Bias toward GREEN (~65%) so
  // a random paste tends to feel like a real ecosystem, not a casino.
  const seed = hash01(wallet);
  let score: number;
  if (seed < 0.65) score = Math.round(range(hash01(wallet + "g"), 800, 980));
  else if (seed < 0.92) score = Math.round(range(hash01(wallet + "y"), 480, 780));
  else score = Math.round(range(hash01(wallet + "r"), 120, 380));
  const { tier, code } = tierFromScore(score);
  return { score, tier, code, immediate_red: code === 2 && hash01(wallet + "ir") > 0.5 };
}

// ─────────────────────────────────────────────────────────────────────────────
// Time helpers — anchored to RUNTIME now, not a fixed date, so timestamps
// in the demo look like "12m ago" instead of "730d ago" no matter when the
// site is rendered.
//
// Determinism note: this makes server-rendered output non-deterministic
// in time — but the SCORES are still deterministic per wallet, which is
// what matters for share-the-link demos. Time just looks current.
// ─────────────────────────────────────────────────────────────────────────────

const EPOCH_SECONDS = 86_400;                       // 24h
const CURRENT_EPOCH = 287;

function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}

function epochAt(epoch: number): string {
  // Epoch CURRENT_EPOCH ends now; older epochs are EPOCH_SECONDS apart.
  // Subtract 14 minutes from the "current" so a fresh cert reads as
  // "14m ago" rather than "0s ago" (which would imply the cert was minted
  // this exact second — implausible).
  const computedOffset = epoch === CURRENT_EPOCH ? 14 * 60 : 0;
  const t = nowUnix() - (CURRENT_EPOCH - epoch) * EPOCH_SECONDS - computedOffset;
  return new Date(t * 1000).toISOString();
}

// ─────────────────────────────────────────────────────────────────────────────
// The mock API
// ─────────────────────────────────────────────────────────────────────────────

export const mockApi = {
  async getAgentHealth(wallet: string): Promise<HealthResponse | null> {
    if (wallet === "404" || wallet === "not-found") return null;
    const s = syntheticScore(wallet);
    return {
      _v: 1,
      agent_wallet: wallet,
      epoch: CURRENT_EPOCH,
      score: s.score,
      alert_tier: s.tier,
      alert_tier_code: s.code,
      flags: Math.floor(hash01(wallet + "f") * 0xff),
      immediate_red: s.immediate_red,
      signer_count: 3 + Math.floor(hash01(wallet + "sc") * 3),  // 3..5
      computed_at: epochAt(CURRENT_EPOCH),
    };
  },

  async getAgentHistory(wallet: string, limit = 30): Promise<HistoryResponse> {
    const cur = syntheticScore(wallet);
    const entries = [];
    // Generate `limit` epochs walking back, with a believable noise
    // pattern around the current score. Featured agents get scripted
    // patterns matching their story.
    for (let i = 0; i < limit; i++) {
      const epoch = CURRENT_EPOCH - i;
      const drift = (hash01(wallet + ":" + epoch) - 0.5) * 80;
      let score = Math.max(0, Math.min(1000, Math.round(cur.score + drift)));
      // Tell the "recovering" story: epochs > 270 dip, before that improve.
      if (wallet.includes("Recovering") && epoch < 270) score -= 250;
      if (wallet.includes("Drifting")   && epoch < 280) score += 200;
      const { tier, code } = tierFromScore(score);
      entries.push({
        epoch,
        score,
        alert_tier: tier,
        alert_tier_code: code,
        immediate_red: code === 2 && hash01(`${wallet}:${epoch}:ir`) > 0.7,
        signer_count: 3 + Math.floor(hash01(`${wallet}:${epoch}:sc`) * 3),
        computed_at: epochAt(epoch),
      });
    }
    return { _v: 1, agent_wallet: wallet, entries, from_epoch: null, to_epoch: null, limit };
  },

  async getClusterHealth(): Promise<ClusterHealthResponse> {
    const now = nowUnix();
    const heartbeats = Array.from({ length: 5 }, (_, i) => ({
      node: `oracle-node-${i}`,
      last_seen_unix: now - (i === 2 ? 240 : 12 + Math.floor(hash01(`hb${i}`) * 8)),
      epoch: CURRENT_EPOCH,
    }));
    const recent_epochs = Array.from({ length: 10 }, (_, i) => {
      const epoch = CURRENT_EPOCH - i;
      const submitted = i === 3 ? 47 : 50;
      const byz = i === 3 ? ["oracle-node-2"] : [];
      return {
        epoch,
        submitted_count: submitted,
        agent_count: 50,
        verified_nodes: ["oracle-node-0", "oracle-node-1", "oracle-node-3", "oracle-node-4"]
          .concat(i === 3 ? [] : ["oracle-node-2"]),
        byzantine_nodes: byz,
        unreachable_nodes: i === 3 ? [] : [],
        elapsed_seconds: 5.8 + hash01(`e${epoch}`) * 1.4,
        computed_at: epochAt(epoch),
      };
    });
    return { _v: 1, heartbeats, recent_epochs };
  },

  async getByzantineRecent(): Promise<ByzantineRecentResponse> {
    return {
      _v: 1,
      since_epoch: null,
      flags: [
        {
          node: "oracle-node-2",
          epoch: 284,
          subject_agent: FEATURED_AGENTS[3].wallet,
          accused_score: 412,
          cluster_median: 184,
          deviation: 1.24,
        },
      ],
    };
  },

  async getStrikeSummary(): Promise<StrikeSummaryResponse> {
    return {
      _v: 1,
      summary: {
        "oracle-node-2": { strikes: 1, flagged_epochs: [284], challenged: false },
      },
    };
  },

  async getChallenges(node: string): Promise<ChallengesResponse> {
    return { _v: 1, accused_node: node, challenges: [] };
  },

  async getVersion(): Promise<VersionResponse> {
    return {
      _v: 1,
      api_version: "0.1.0",
      scoring_algo_version: "v2.7",
      scoring_weights_version: "w1",
      network: "devnet",
      network_is_production: false,
    };
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Featured agents for the landing ticker
// ─────────────────────────────────────────────────────────────────────────────

export const RECENT_TICKER_ITEMS = FEATURED_AGENTS.map((a) => ({
  wallet: a.wallet,
  label: a.label,
  score: a.score,
  tier: a.tier,
}));
