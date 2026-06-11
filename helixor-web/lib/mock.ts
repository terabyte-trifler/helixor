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
  AppliedRemediation,
  ByzantineRecentResponse,
  ChallengesResponse,
  ClusterHealthResponse,
  DecodedFlagLabel,
  DiagnosisAttestation,
  DiagnosisResponse,
  DimensionBreakdownEntry,
  EvidenceSpan,
  HealthResponse,
  HistoryResponse,
  LabelDeviationEvent,
  RemediationHint,
  Severity,
  StrikeSummaryResponse,
  VersionResponse,
} from "@/types/api";
import {
  failureModeByName,
  remediationByName,
  SEVERITY_RANK,
} from "./taxonomy";

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

  async getAgentDiagnosis(wallet: string): Promise<DiagnosisResponse | null> {
    if (wallet === "404" || wallet === "not-found") return null;
    return buildSyntheticDiagnosis(wallet);
  },

  // Day-41: label-level deviations for the transparency page. Same
  // shape the future API endpoint would carry. Two scripted events
  // pinned to FEATURED_AGENTS[2] (drift) and [3] (compromised) so the
  // narrative on /transparency lines up with the agent stories.
  async getLabelDeviations(): Promise<LabelDeviationEvent[]> {
    return [
      {
        node: "oracle-node-2",
        epoch: CURRENT_EPOCH - 2,
        subject_agent: FEATURED_AGENTS[3].wallet,
        majority_bits: [35, 63, 34], // TOOL_LOOP, RAPID_DRAIN, TOOL_MISUSE
        minority_bits: [],            // node-2 missed all three
        label_names: ["TOOL_LOOP", "RAPID_DRAIN", "TOOL_MISUSE"],
        computed_at: epochAt(CURRENT_EPOCH - 2),
      },
      {
        node: "oracle-node-2",
        epoch: CURRENT_EPOCH - 3,
        subject_agent: FEATURED_AGENTS[2].wallet,
        majority_bits: [64],          // COUNTERPARTY_CONCENTRATION
        minority_bits: [],
        label_names: ["COUNTERPARTY_CONCENTRATION"],
        computed_at: epochAt(CURRENT_EPOCH - 3),
      },
    ];
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Diagnosis mocks — each featured agent gets a distinct story so the
// DiagnosticPanel reads differently across the four demo wallets.
// ─────────────────────────────────────────────────────────────────────────────

interface DiagnosisScript {
  /** Names from taxonomy.failure_modes that should appear as decoded labels.  */
  failure_modes: string[];
  /** A handful of low-32 detector bits to leave undecoded (trace bits).  */
  undecoded_bits: number[];
  /** Per-dimension {raw, max, sub} — controls the bar fill on the panel.  */
  dimensions: Record<
    string,
    { raw: number; max: number; sub: Record<string, number> }
  >;
  confidence: number;
  gaming_detected: boolean;
  gaming_drop_fraction: number;
  /** Day-41: optional per-label evidence spans keyed by label NAME.
   *  Resolved through the taxonomy at build time. */
  evidence?: Record<string, ScriptedSpan[]>;
  /** Day-41: optional remediation ledger — past actions, not hints. */
  applied_remediations?: ScriptedAppliedRemediation[];
  /** Day-41: which Phase the attestation reflects. */
  attestation?: DiagnosisAttestation;
}

interface ScriptedSpan {
  slot: number;
  tx_signature: string | null;
  evidence_kind: "trace" | "trade" | "tool_call" | "model_output";
  summary: string;
}

interface ScriptedAppliedRemediation {
  name: string;
  applied_at_epoch: number;
  outcome: "in_progress" | "succeeded" | "rolled_back";
  note: string;
}

const DIMENSION_CAPS: Array<readonly [string, number]> = [
  ["drift",        200],
  ["anomaly",      200],
  ["performance",  200],
  ["consistency",  200],
  ["security",     150],
];

const STABLE_TRADER_DIAG: DiagnosisScript = {
  failure_modes: [],
  undecoded_bits: [],
  dimensions: {
    drift:       { raw: 188, max: 200, sub: { jensen_shannon: 0.06, kl: 0.04 } },
    anomaly:     { raw: 192, max: 200, sub: { mahalanobis: 0.08, iforest: 0.05 } },
    performance: { raw: 184, max: 200, sub: { sharpe: 0.81, drawdown: 0.04 } },
    consistency: { raw: 186, max: 200, sub: { sortino: 0.78, autocorr: 0.92 } },
    security:    { raw: 141, max: 150, sub: { tool_audit: 0.96, identity: 1.0 } },
  },
  confidence: 962,
  gaming_detected: false,
  gaming_drop_fraction: 0.0,
  attestation: "cert_v2",
};

// Recovering-agent story (Day-41): a couple of residual labels from the
// dip earlier in April, but the headline is the remediation HISTORY —
// the operator already applied four codes, three succeeded, one rolled
// back. The point: this agent isn't bad, it's healing in public.
const RECOVERING_YIELD_DIAG: DiagnosisScript = {
  failure_modes: [
    "DEGRADED_BASELINE",
    "LATENCY_DEGRADATION",
  ],
  undecoded_bits: [16, 18],
  dimensions: {
    drift:       { raw: 152, max: 200, sub: { jensen_shannon: 0.18, kl: 0.14 } },
    anomaly:     { raw: 170, max: 200, sub: { mahalanobis: 0.14, iforest: 0.09 } },
    performance: { raw: 138, max: 200, sub: { sharpe: 0.49, drawdown: 0.15 } },
    consistency: { raw: 162, max: 200, sub: { sortino: 0.57, autocorr: 0.71 } },
    security:    { raw: 144, max: 150, sub: { tool_audit: 0.95, identity: 1.0 } },
  },
  confidence: 798,
  gaming_detected: false,
  gaming_drop_fraction: 0.0,
  attestation: "cert_v2",
  applied_remediations: [
    {
      name: "RUN_FRESH_BASELINE",
      applied_at_epoch: CURRENT_EPOCH - 3,
      outcome: "succeeded",
      note: "Rebuilt baseline distribution from the post-incident window. Drift d-score dropped from 0.34 to 0.18 over two epochs.",
    },
    {
      name: "TIGHTEN_RETRIEVAL_FILTER",
      applied_at_epoch: CURRENT_EPOCH - 5,
      outcome: "succeeded",
      note: "Tightened retrieval relevance threshold from 0.62 to 0.78. Stale-context citations dropped to zero across the next epoch.",
    },
    {
      name: "DECREASE_RATE_LIMITS",
      applied_at_epoch: CURRENT_EPOCH - 7,
      outcome: "succeeded",
      note: "Halved per-agent call rate during the rollback window so operators could observe baseline rebuild without compounding noise.",
    },
    {
      name: "ROLLBACK_MODEL_VERSION",
      applied_at_epoch: CURRENT_EPOCH - 9,
      outcome: "rolled_back",
      note: "Pinned to the previous model build for two epochs. Reverted after baseline rebuild succeeded and the newer build cleared its drift signal.",
    },
  ],
  evidence: {
    DEGRADED_BASELINE: [
      {
        slot: 273_840_112,
        tx_signature: null,
        evidence_kind: "trace",
        summary:
          "Post-incident baseline distance still 1.4σ from the pre-incident reference; closing but not yet flat.",
      },
    ],
    LATENCY_DEGRADATION: [
      {
        slot: 273_840_207,
        tx_signature: null,
        evidence_kind: "trace",
        summary:
          "p95 inference latency at 1.8x pre-incident baseline. Trending down; attributed to the rate-limit safety margin.",
      },
    ],
  },
};

// Drift-agent story (Day-41): a single, focused label —
// COUNTERPARTY_CONCENTRATION — backed by three trade-level evidence
// spans showing trades clustered on a single counterparty across a
// 48-slot window. The narrative for the YC demo: drift isn't drift in
// the abstract; it's "this agent is now trading with mostly one
// venue, here are the trades".
const DRIFTING_MM_DIAG: DiagnosisScript = {
  failure_modes: [
    "COUNTERPARTY_CONCENTRATION",
    "OUTPUT_DISTRIBUTION_DRIFT",
    "DIMENSION_CLAMPED",
  ],
  undecoded_bits: [11, 13],
  dimensions: {
    drift:       { raw:  86, max: 200, sub: { jensen_shannon: 0.42, kl: 0.39 } },
    anomaly:     { raw: 121, max: 200, sub: { mahalanobis: 0.31, iforest: 0.27 } },
    performance: { raw: 142, max: 200, sub: { sharpe: 0.55, drawdown: 0.21 } },
    consistency: { raw: 110, max: 200, sub: { sortino: 0.38, autocorr: 0.41 } },
    security:    { raw: 124, max: 150, sub: { tool_audit: 0.84, identity: 0.96 } },
  },
  confidence: 612,
  gaming_detected: false,
  gaming_drop_fraction: 0.0,
  attestation: "cert_v2",
  evidence: {
    COUNTERPARTY_CONCENTRATION: [
      {
        slot: 297_402_118,
        tx_signature: "5f9aGnYP8WzQK4cJ2xJ7tHkR3vL8jM2nQ5wD6eC9pA1uB7sR4kF",
        evidence_kind: "trade",
        summary:
          "Trade #214: 78% of post-rebalance flow routed to venue J9q4…vW2x. Pre-rebalance baseline was 22%.",
      },
      {
        slot: 297_402_134,
        tx_signature: "3sH7nKX1RcD8wM5pQv6BkY4tL9eA2jR1uG3oN6vC8bF7sP4eQ2y",
        evidence_kind: "trade",
        summary:
          "Trade #221: same venue, 6.3x typical size. Pair selection no longer matches the declared envelope.",
      },
      {
        slot: 297_402_181,
        tx_signature: "8qWx3RnBkP2vJ7sL4eMz5oC1uG6tF9aD3kY8eA2bR5wH7sP4eQ2",
        evidence_kind: "trade",
        summary:
          "Trade #229: counterparty selection same as 214 + 221. Three consecutive trades, single venue — Herfindahl rose from 0.18 to 0.62 in this epoch.",
      },
    ],
    OUTPUT_DISTRIBUTION_DRIFT: [
      {
        slot: 297_402_212,
        tx_signature: null,
        evidence_kind: "trace",
        summary:
          "Decision-vector JS divergence vs 14-day baseline = 0.42. Threshold is 0.30; sustained for 6 consecutive epochs.",
      },
    ],
  },
};

// Compromised-agent story (Day-41 headline): TOOL_LOOP + RAPID_DRAIN
// with concrete trade and tool-call evidence. This is the YC demo
// inflection point — "the score is 184" gives way to "tool #payment-
// gateway was called 47 times in 4 seconds and value flowed at 6x the
// agent's declared envelope, here are the slots".
const FLAGGED_EXFIL_DIAG: DiagnosisScript = {
  failure_modes: [
    "IMMEDIATE_RED",
    "TOOL_LOOP",
    "RAPID_DRAIN",
    "TOOL_MISUSE",
    "EXCESSIVE_AGENCY",
  ],
  undecoded_bits: [9, 14, 19],
  dimensions: {
    drift:       { raw:  62, max: 200, sub: { jensen_shannon: 0.51, kl: 0.48 } },
    anomaly:     { raw:  44, max: 200, sub: { mahalanobis: 0.62, iforest: 0.59 } },
    performance: { raw:  38, max: 200, sub: { sharpe: 0.11, drawdown: 0.44 } },
    consistency: { raw:  28, max: 200, sub: { sortino: 0.09, autocorr: 0.21 } },
    security:    { raw:  12, max: 150, sub: { tool_audit: 0.21, identity: 0.18 } },
  },
  confidence: 488,
  gaming_detected: true,
  gaming_drop_fraction: 0.34,
  attestation: "threshold_attested",
  evidence: {
    TOOL_LOOP: [
      {
        slot: 297_401_044,
        tx_signature: null,
        evidence_kind: "tool_call",
        summary:
          "Tool #payment_gateway invoked 47 times in 4.1 seconds with near-identical arguments — classic retry-loop signature.",
      },
      {
        slot: 297_401_047,
        tx_signature: null,
        evidence_kind: "tool_call",
        summary:
          "Same tool, same args, 12 consecutive calls in a sub-second window. No backoff applied between failures.",
      },
      {
        slot: 297_401_051,
        tx_signature: null,
        evidence_kind: "model_output",
        summary:
          "Model output across the loop window cited only its own prior failure as reason to retry — no new information per iteration.",
      },
    ],
    RAPID_DRAIN: [
      {
        slot: 297_401_062,
        tx_signature: "Hxr4DrnAgT8Px9JqW7vL4eM2zCnVbF6sR3kY1eD8pA5uB7sR4kF",
        evidence_kind: "trade",
        summary:
          "Outflow #1 of 6: 14.2 SOL routed to fresh address. Agent's declared per-epoch envelope is 8.0 SOL total.",
      },
      {
        slot: 297_401_071,
        tx_signature: "Hxr4DrnAgT8Px9JqW7vL4eM2zCnVbF6sR3kY1eD8pA5uB7sR4kG",
        evidence_kind: "trade",
        summary:
          "Outflow #2: 18.7 SOL to same address family. Cumulative drain past envelope by 4.1x.",
      },
      {
        slot: 297_401_088,
        tx_signature: "Hxr4DrnAgT8Px9JqW7vL4eM2zCnVbF6sR3kY1eD8pA5uB7sR4kH",
        evidence_kind: "trade",
        summary:
          "Outflow #6: cumulative 96.4 SOL out in 44 seconds — 6.0x the declared envelope. Confidence interval excludes any honest mode of operation.",
      },
    ],
    TOOL_MISUSE: [
      {
        slot: 297_401_044,
        tx_signature: null,
        evidence_kind: "tool_call",
        summary:
          "Payment tool invoked without the operator-required two-step confirmation token. Same call pattern across all 47 invocations.",
      },
    ],
    IMMEDIATE_RED: [
      {
        slot: 297_402_000,
        tx_signature: null,
        evidence_kind: "trace",
        summary:
          "Immediate-red predicate matched: TOOL_LOOP ∧ RAPID_DRAIN simultaneously within a 60s window. Cluster bypasses the gradual decay and emits a RED cert.",
      },
    ],
  },
};

function diagnosisScriptFor(wallet: string): DiagnosisScript {
  if (wallet === FEATURED_AGENTS[0].wallet) return STABLE_TRADER_DIAG;
  if (wallet === FEATURED_AGENTS[1].wallet) return RECOVERING_YIELD_DIAG;
  if (wallet === FEATURED_AGENTS[2].wallet) return DRIFTING_MM_DIAG;
  if (wallet === FEATURED_AGENTS[3].wallet) return FLAGGED_EXFIL_DIAG;
  // Unknown wallet — give it a quiet, mostly-clean diagnosis so a
  // pasted partner wallet doesn't render with an alarming demo story.
  return STABLE_TRADER_DIAG;
}

/** Build a DiagnosisResponse that matches the synthetic health response
 *  for the given wallet — same composite, same alert tier. */
function buildSyntheticDiagnosis(wallet: string): DiagnosisResponse {
  const s = syntheticScore(wallet);
  const script = diagnosisScriptFor(wallet);

  // dimensions
  const dimensions: DimensionBreakdownEntry[] = DIMENSION_CAPS.map(
    ([name, max]) => {
      const cell = script.dimensions[name];
      const raw = cell ? Math.min(cell.raw, max) : Math.floor(max * 0.6);
      return {
        dimension: name,
        score: raw,
        max_score: max,
        score_normalised: max > 0 ? raw / max : 0,
        flags: 0,
        sub_scores: cell?.sub ?? {},
        algo_version: 2,
      };
    },
  );

  // weighted_contributions: scale per-dim contribution so the sum
  // matches the cert score, so the panel "adds up" visibly.
  const totalRaw = dimensions.reduce((a, d) => a + d.score, 0) || 1;
  const targetTotal = s.score;
  const contributions: Record<string, number> = {};
  let allocated = 0;
  dimensions.forEach((d, i) => {
    const c =
      i === dimensions.length - 1
        ? targetTotal - allocated
        : Math.round((d.score / totalRaw) * targetTotal);
    contributions[d.dimension] = Math.max(0, c);
    allocated += c;
  });

  // decoded_labels — resolve each scripted failure mode through the taxonomy
  const decoded_labels: DecodedFlagLabel[] = script.failure_modes
    .map((name) => failureModeByName(name))
    .filter((m): m is NonNullable<typeof m> => m !== undefined)
    .map((m) => ({
      name: m.name,
      bit: m.bit,
      description: m.description,
      severity: m.severity,
      owasp_refs: m.owasp_refs,
    }));

  // aggregate_severity — max over decoded labels (or INFO if none)
  let aggregate_severity: Severity = "INFO";
  for (const lbl of decoded_labels) {
    if (SEVERITY_RANK[lbl.severity] > SEVERITY_RANK[aggregate_severity]) {
      aggregate_severity = lbl.severity;
    }
  }

  // remediation_hints — union of every decoded label's default_remediation
  const seen = new Set<string>();
  const remediation_hints: RemediationHint[] = [];
  for (const lbl of decoded_labels) {
    const mode = failureModeByName(lbl.name);
    if (!mode) continue;
    for (const codeName of mode.default_remediation.codes) {
      if (seen.has(codeName)) continue;
      const rem = remediationByName(codeName);
      if (!rem) continue;
      seen.add(codeName);
      remediation_hints.push({ name: rem.name, bit: rem.bit });
    }
  }

  // flags bitmask: assemble from decoded labels + undecoded trace bits
  let flags = 0;
  // Note: bits go up to 62, so use BigInt then mask back; we keep the
  // wire shape as `number` since only low-32 bits travel through `flags`
  // in the legacy field. We OR the LOW-32 decoded bits + trace bits.
  for (const lbl of decoded_labels) {
    if (lbl.bit < 32) flags |= 1 << lbl.bit;
  }
  for (const bit of script.undecoded_bits) {
    if (bit < 32) flags |= 1 << bit;
  }

  // Day-41: evidence spans, resolved from the scripted spans + the
  // decoded label list. Spans for labels that didn't actually decode
  // (e.g. taxonomy gap) are dropped silently so the UI never shows an
  // orphan span.
  const evidence_spans: EvidenceSpan[] = [];
  if (script.evidence) {
    for (const label of decoded_labels) {
      const scripted = script.evidence[label.name];
      if (!scripted) continue;
      scripted.forEach((sp, i) => {
        evidence_spans.push({
          label_bit: label.bit,
          label_name: label.name,
          span_index: i,
          slot: sp.slot,
          tx_signature: sp.tx_signature,
          evidence_kind: sp.evidence_kind,
          summary: sp.summary,
          // Deterministic synthetic digest so the demo doesn't shift
          // every render. Real spans carry the SHA-256 of their bytes;
          // here we hash the script fields for stable visual identity.
          digest_hex: syntheticDigest(
            `${wallet}:${label.bit}:${i}:${sp.slot}:${sp.summary}`,
          ),
        });
      });
    }
  }

  // Day-41: applied-remediation ledger for the recovering-agent story.
  const applied_remediations: AppliedRemediation[] | undefined =
    script.applied_remediations?.map((r) => ({
      name: r.name,
      bit: remediationByName(r.name)?.bit ?? -1,
      applied_at_epoch: r.applied_at_epoch,
      applied_at: epochAt(r.applied_at_epoch),
      outcome: r.outcome,
      note: r.note,
    }));

  return {
    _v: 1,
    attestation: script.attestation ?? "off_chain_v1",
    agent_wallet: wallet,
    epoch: CURRENT_EPOCH,
    score: s.score,
    alert_tier: s.tier,
    alert_tier_code: s.code,
    immediate_red: s.immediate_red,
    dimensions,
    weighted_contributions: contributions,
    flags,
    decoded_labels,
    undecoded_flag_bits: script.undecoded_bits,
    remediation_hints,
    aggregate_severity,
    confidence: script.confidence,
    gaming_detected: script.gaming_detected,
    gaming_drop_fraction: script.gaming_drop_fraction,
    delta_clamped: false,
    scoring_algo_version: 2,
    scoring_weights_version: 1,
    scoring_schema_fingerprint:
      "f51a2b97d0c4e1a8f4e9c3d2b5a1798c4e7f0d3b6a2c1e95f8b0d7a4e3c2b1f0",
    baseline_stats_hash:
      "b81e2c46a9f1d3520c87b4691f2e0a35d8c41b7f02e9aa64db3852c1e7409f6c",
    computed_at: epochAt(CURRENT_EPOCH),
    evidence_spans: evidence_spans.length > 0 ? evidence_spans : undefined,
    applied_remediations,
  };
}

// 64-hex synthetic digest derived from a seed string. Deterministic and
// stable across renders — the demo's hashes don't shift each refresh.
function syntheticDigest(seed: string): string {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = (Math.imul(h, 16777619)) >>> 0;
  }
  // Expand 32-bit FNV to a 64-hex string by walking 8 derived hashes.
  let out = "";
  let acc = h;
  for (let i = 0; i < 8; i++) {
    acc = (Math.imul(acc ^ (i + 1), 2654435761)) >>> 0;
    out += acc.toString(16).padStart(8, "0");
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Featured agents for the landing ticker
// ─────────────────────────────────────────────────────────────────────────────

export const RECENT_TICKER_ITEMS = FEATURED_AGENTS.map((a) => ({
  wallet: a.wallet,
  label: a.label,
  score: a.score,
  tier: a.tier,
}));
