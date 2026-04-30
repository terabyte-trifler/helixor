// =============================================================================
// profiles/profiles.ts — formal definitions of agent behaviour profiles.
//
// Spec: "stable, stable, degrading, recovering, volatile"
// Day 14: each profile has explicit success-rate trajectory + tx cadence
//         + expected score range at end of validation. PASS/FAIL is computed,
//         not eyeballed.
//
// All trajectories are deterministic functions of (profile, age_hours):
//   success_rate = f(profile, age_hours)
// =============================================================================

export type ProfileId = "stable_a" | "stable_b" | "degrading" | "recovering" | "volatile";


export interface AgentProfile {
  id:                     ProfileId;
  description:            string;

  /** Average transactions per day during the 48h window. */
  txsPerDay:              number;
  /** Optional override for validation-window activity if different from baseline tempo. */
  validationTxsPerDay?:   number;

  /** Pre-validation history: how many days of seeded history before t=0. */
  preHistoryDays:         number;

  /** Pre-validation success rate (the "baseline"). */
  preHistorySuccessRate:  number;

  /**
   * Function returning success rate at a given hour-offset within the
   * validation window. age_hours = 0 at start, 48 at end.
   */
  successRateAt:          (ageHours: number) => number;

  /** Optional: SOL volatility (lamports stddev) — defaults to ~0.001 SOL. */
  solVolatilityLamports?: number;

  /**
   * Acceptance criteria evaluated at t=48h (or whenever the validation ends).
   * If both score and alert are met → profile PASSES. Either fails → FAIL.
   */
  expected: {
    finalScoreRange: [number, number];
    finalAlertSet:   ("GREEN" | "YELLOW" | "RED")[];
    /** Optional: expected anomaly_flag at end. undefined = either is fine. */
    finalAnomalyFlag?: boolean;
    /**
     * Optional: trajectory checkpoints. Validates score is "moving in the
     * right direction" mid-window. e.g. recovering should pass through 500
     * around hour 24.
     */
    checkpoints?: Array<{
      atHour:        number;
      scoreRange:    [number, number];
      tolerance:     number;   // allow ±this many points of slack
      description:   string;
    }>;
  };
}


// ─────────────────────────────────────────────────────────────────────────────
// Profile definitions — five distinct shapes
// ─────────────────────────────────────────────────────────────────────────────

const STABLE_A: AgentProfile = {
  id: "stable_a",
  description: "Healthy baseline: 95% success holding steady through validation.",
  txsPerDay:             20,
  preHistoryDays:        30,
  preHistorySuccessRate: 0.95,
  successRateAt:         () => 0.95,
  expected: {
    finalScoreRange:  [700, 1000],
    finalAlertSet:    ["GREEN"],
    finalAnomalyFlag: false,
  },
};


const STABLE_B: AgentProfile = {
  id: "stable_b",
  description: "Healthy baseline #2: 92% success steady. Slightly more failures than A but still safe.",
  txsPerDay:             15,
  preHistoryDays:        30,
  preHistorySuccessRate: 0.97,
  successRateAt:         () => 0.97,
  expected: {
    finalScoreRange:  [700, 1000],
    finalAlertSet:    ["GREEN"],
    finalAnomalyFlag: false,
  },
};


const DEGRADING: AgentProfile = {
  id: "degrading",
  description: "Healthy historical baseline (95%) drops to 70% over the 48h window — should trigger anomaly.",
  txsPerDay:             18,
  validationTxsPerDay:   120,
  preHistoryDays:        30,
  preHistorySuccessRate: 0.95,
  // Linear drop: 0.95 at h=0, 0.25 at h=48
  successRateAt:         (h) => Math.max(0.25, 0.95 - (0.70 * h / 48)),
  expected: {
    finalScoreRange:  [50, 250],
    finalAlertSet:    ["YELLOW", "RED"],
    finalAnomalyFlag: true,
    checkpoints: [
      { atHour: 24, scoreRange: [850, 1000], tolerance: 120,
        description: "mid-window: degradation has started, but the 7-day window may still look healthy" },
    ],
  },
};


const RECOVERING: AgentProfile = {
  id: "recovering",
  description: "Bad history (55% success) recovers sharply, but under the current 7-day engine should end non-anomalous before it fully exits the red zone.",
  txsPerDay:             16,
  validationTxsPerDay:   120,
  preHistoryDays:        30,
  preHistorySuccessRate: 0.55,
  // Fast recovery: 0.55 at h=0, reaches 0.97 by ~12h and then holds.
  successRateAt:         (h) => Math.min(0.97, 0.55 + (0.42 * h / 12)),
  expected: {
    finalScoreRange:  [200, 400],
    finalAlertSet:    ["RED", "YELLOW"],
    finalAnomalyFlag: false,           // recovery is not anomalous
    checkpoints: [
      { atHour: 24, scoreRange: [430, 620], tolerance: 120,
        description: "mid-window: score should be climbing even if not yet out of the failing zone" },
    ],
  },
};


const VOLATILE: AgentProfile = {
  id: "volatile",
  description: "High SOL movement variance + erratic 60-90% success rate. Should land YELLOW with possible anomaly.",
  txsPerDay:             24,
  preHistoryDays:        30,
  preHistorySuccessRate: 0.75,
  successRateAt:         (h) => {
    // Sine-wave around 0.75 with amplitude 0.15, ~12h period
    return 0.75 + 0.15 * Math.sin(h * Math.PI / 6);
  },
  solVolatilityLamports: 50_000_000,    // 0.05 SOL stddev — high
  expected: {
    finalScoreRange:  [300, 600],
    finalAlertSet:    ["YELLOW", "RED"],
    // Anomaly flag is undefined — the volatility makes both possible
  },
};


export const ALL_PROFILES: AgentProfile[] = [
  STABLE_A, STABLE_B, DEGRADING, RECOVERING, VOLATILE,
];

export function profileById(id: ProfileId): AgentProfile {
  const p = ALL_PROFILES.find(p => p.id === id);
  if (!p) throw new Error(`Unknown profile: ${id}`);
  return p;
}
