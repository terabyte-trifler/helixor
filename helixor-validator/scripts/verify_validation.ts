#!/usr/bin/env tsx
// =============================================================================
// scripts/verify_validation.ts — compute PASS/FAIL from accumulated state.
//
// Each profile has acceptance criteria (final score range, alert set,
// anomaly flag, mid-window checkpoints). This script evaluates EVERY
// criterion and prints a structured verdict. Exit 0 = pass, 1 = fail.
// =============================================================================

import { loadEnv } from "../helpers/env";
import { findActiveRun, loadState, type ValidationState } from "../helpers/state";
import { profileById } from "../profiles/profiles";


interface Verdict {
  profileId:          string;
  agentWallet:        string;
  passed:             boolean;
  reasons:            string[];
  finalSnapshot:      {
    hourOffset: number;
    score:      number | null;
    alert:      string | null;
    anomalyFlag: boolean | null;
    isFresh:     boolean | null;
  } | null;
  checkpointResults:  Array<{ atHour: number; passed: boolean; description: string; score: number | null; }>;
}


function findClosestSnapshot(
  state: ValidationState,
  agent: string,
  targetHour: number,
  toleranceHours = 1.0,
): ValidationState["snapshots"][0] | null {
  const candidates = state.snapshots
    .filter(s => s.agentWallet === agent && s.score !== null)
    .filter(s => Math.abs(s.hourOffset - targetHour) <= toleranceHours);
  if (candidates.length === 0) return null;
  candidates.sort((a, b) => Math.abs(a.hourOffset - targetHour) - Math.abs(b.hourOffset - targetHour));
  return candidates[0]!;
}


function findFinalSnapshot(state: ValidationState, agent: string): ValidationState["snapshots"][0] | null {
  const all = state.snapshots
    .filter(s => s.agentWallet === agent && s.score !== null);
  if (all.length === 0) return null;
  all.sort((a, b) => b.hourOffset - a.hourOffset);   // newest first
  return all[0]!;
}


function evaluate(state: ValidationState): { verdicts: Verdict[]; allPassed: boolean } {
  const verdicts: Verdict[] = [];
  const profileSnapshotStepHours = state.durationHours > 0
    ? (state.snapshotIntervalMinutes / 60) * (48 / state.durationHours)
    : 48;
  const checkpointToleranceHours = Math.max(1.0, profileSnapshotStepHours + 0.5);

  for (const a of state.agents) {
    const profile = profileById(a.profileId);
    const final   = findFinalSnapshot(state, a.agentWallet);

    const reasons: string[] = [];
    let passed = true;

    if (!final) {
      reasons.push("no successful snapshot was ever taken");
      verdicts.push({
        profileId: a.profileId, agentWallet: a.agentWallet,
        passed: false, reasons,
        finalSnapshot: null, checkpointResults: [],
      });
      continue;
    }

    const exp = profile.expected;

    // 1. Final score range
    if (final.score! < exp.finalScoreRange[0] || final.score! > exp.finalScoreRange[1]) {
      passed = false;
      reasons.push(
        `final score ${final.score} outside expected range ` +
        `[${exp.finalScoreRange[0]}, ${exp.finalScoreRange[1]}]`,
      );
    } else {
      reasons.push(`final score ${final.score} ∈ [${exp.finalScoreRange[0]},${exp.finalScoreRange[1]}] ✓`);
    }

    // 2. Final alert
    if (!exp.finalAlertSet.includes(final.alert as any)) {
      passed = false;
      reasons.push(
        `final alert ${final.alert} not in expected set [${exp.finalAlertSet.join(",")}]`,
      );
    } else {
      reasons.push(`final alert ${final.alert} ∈ [${exp.finalAlertSet.join(",")}] ✓`);
    }

    // 3. Anomaly flag (if specified)
    if (exp.finalAnomalyFlag !== undefined) {
      if (final.anomalyFlag !== exp.finalAnomalyFlag) {
        passed = false;
        reasons.push(
          `anomaly_flag=${final.anomalyFlag}, expected ${exp.finalAnomalyFlag}`,
        );
      } else {
        reasons.push(`anomaly_flag=${final.anomalyFlag} ✓`);
      }
    }

    // 4. is_fresh — every passing agent must have a fresh score at end
    if (final.isFresh === false) {
      passed = false;
      reasons.push(`is_fresh=false at end of validation (epoch_runner stuck?)`);
    }

    // 5. Checkpoint trajectories
    const checkpointResults: Verdict["checkpointResults"] = [];
    for (const cp of exp.checkpoints ?? []) {
      const snapWithDynamicTolerance = findClosestSnapshot(
        state,
        a.agentWallet,
        cp.atHour,
        checkpointToleranceHours,
      );
      if (!snapWithDynamicTolerance) {
        passed = false;
        checkpointResults.push({
          atHour: cp.atHour, passed: false, description: cp.description, score: null,
        });
        reasons.push(`checkpoint ${cp.atHour}h: no snapshot available`);
        continue;
      }
      const snap = snapWithDynamicTolerance;
      const lo = cp.scoreRange[0] - cp.tolerance;
      const hi = cp.scoreRange[1] + cp.tolerance;
      const ok = snap.score! >= lo && snap.score! <= hi;
      checkpointResults.push({
        atHour: cp.atHour, passed: ok, description: cp.description, score: snap.score,
      });
      if (!ok) {
        passed = false;
        reasons.push(`checkpoint ${cp.atHour}h failed: score ${snap.score} ∉ [${lo},${hi}] (${cp.description})`);
      } else {
        reasons.push(`checkpoint ${cp.atHour}h: ${snap.score} ∈ [${lo},${hi}] ✓`);
      }
    }

    verdicts.push({
      profileId:    a.profileId,
      agentWallet:  a.agentWallet,
      passed, reasons,
      finalSnapshot: {
        hourOffset:  final.hourOffset,
        score:       final.score,
        alert:       final.alert,
        anomalyFlag: final.anomalyFlag,
        isFresh:     final.isFresh,
      },
      checkpointResults,
    });
  }

  return { verdicts, allPassed: verdicts.every(v => v.passed) };
}


async function main(): Promise<number> {
  const env = loadEnv();

  let runId = process.env.HELIXOR_VALIDATION_RUN_ID;
  if (!runId) {
    runId = await findActiveRun(env.stateDir) ?? "";
    if (!runId) {
      console.error("No staged run found.");
      return 1;
    }
  }

  console.log(`\n  Validating runId=${runId}\n`);

  const state = await loadState(env.stateDir, runId);
  const { verdicts, allPassed } = evaluate(state);

  console.log("┌──────────────────────────────────────────────────────────────────┐");
  console.log("│  Verdict per agent                                                │");
  console.log("└──────────────────────────────────────────────────────────────────┘");

  for (const v of verdicts) {
    const mark = v.passed ? "\x1b[32m✓ PASS\x1b[0m" : "\x1b[31m✗ FAIL\x1b[0m";
    console.log(`\n  ${mark}  ${v.profileId.padEnd(11)}  ${v.agentWallet.slice(0, 12)}...`);
    if (v.finalSnapshot) {
      console.log(`         final: score=${v.finalSnapshot.score} alert=${v.finalSnapshot.alert} ` +
                  `anomaly=${v.finalSnapshot.anomalyFlag} fresh=${v.finalSnapshot.isFresh} ` +
                  `(t=${v.finalSnapshot.hourOffset.toFixed(2)}h)`);
    } else {
      console.log(`         final: NO SNAPSHOT TAKEN`);
    }
    for (const r of v.reasons) {
      console.log(`         · ${r}`);
    }
    for (const cp of v.checkpointResults) {
      const cpMark = cp.passed ? "✓" : "✗";
      console.log(`         · checkpoint ${cp.atHour}h ${cpMark}  score=${cp.score}  (${cp.description})`);
    }
  }

  console.log("");
  console.log("┌──────────────────────────────────────────────────────────────────┐");
  if (allPassed) {
    console.log("│  \x1b[32m✓ All 5 agents PASS validation\x1b[0m" + " ".repeat(31) + "│");
  } else {
    const failures = verdicts.filter(v => !v.passed).length;
    console.log(`│  \x1b[31m✗ ${failures}/${verdicts.length} agents FAILED\x1b[0m` + " ".repeat(48) + "│");
  }
  console.log("└──────────────────────────────────────────────────────────────────┘");
  console.log("");

  return allPassed ? 0 : 1;
}


main().then(code => process.exit(code))
      .catch((err) => { console.error(err); process.exit(1); });
