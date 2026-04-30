// =============================================================================
// helpers/state.ts — persistent state for a 48h validation run.
//
// Every script reads/writes this single JSON file. Lets us resume after a
// crash and produce the final report from accumulated data.
//
// File layout: $stateDir/run_{runId}/state.json
// =============================================================================

import fs from "node:fs/promises";
import path from "node:path";

import type { ProfileId } from "../profiles/profiles";


export interface AgentRecord {
  profileId:           ProfileId;
  agentWallet:         string;
  ownerWallet:         string;
  registeredAt:        string;
}

export interface ScoreSnapshot {
  agentWallet:         string;
  hourOffset:          number;
  /** Score may be null if API returned 404 / error at this snapshot. */
  score:               number | null;
  alert:               "GREEN" | "YELLOW" | "RED" | null;
  source:              string | null;
  successRate:         number | null;
  anomalyFlag:         boolean | null;
  isFresh:             boolean | null;
  scoringAlgoVersion:  number | null;
  /** ISO timestamp of when the snapshot was taken. */
  takenAt:             string;
  /** Error message if the API call failed. */
  error?:              string;
}

export interface EpochRecord {
  hourOffset:          number;
  startedAt:           string;
  finishedAt:          string;
  exitCode:            number;
  durationMs:          number;
  scoresSubmitted:     number;
}

export interface InjectionRecord {
  hourOffset:          number;
  agentWallet:         string;
  count:               number;
  successRate:         number;
  takenAt:             string;
}

export interface ValidationState {
  runId:               string;
  /** Defines THE clock for the entire run. */
  startedAt:           string;
  /** Optional: when the run finished. Until set, run is still active. */
  finishedAt?:         string;
  /** How long the run is configured to take. */
  durationHours:       number;
  /** Snapshot cadence in minutes. */
  snapshotIntervalMinutes: number;

  agents:              AgentRecord[];
  snapshots:           ScoreSnapshot[];
  epochs:              EpochRecord[];
  injections:          InjectionRecord[];
}


export function newState(opts: {
  runId:        string;
  durationHours: number;
  snapshotIntervalMinutes: number;
}): ValidationState {
  return {
    runId:        opts.runId,
    startedAt:    new Date().toISOString(),
    durationHours: opts.durationHours,
    snapshotIntervalMinutes: opts.snapshotIntervalMinutes,
    agents: [],
    snapshots: [],
    epochs: [],
    injections: [],
  };
}


export function statePath(stateDir: string, runId: string): string {
  return path.join(stateDir, `run_${runId}`, "state.json");
}


export async function saveState(stateDir: string, state: ValidationState): Promise<void> {
  const file = statePath(stateDir, state.runId);
  await fs.mkdir(path.dirname(file), { recursive: true });
  // Atomic-ish write: write to .tmp, rename
  const tmp = file + ".tmp";
  await fs.writeFile(tmp, JSON.stringify(state, null, 2));
  await fs.rename(tmp, file);
}


export async function loadState(stateDir: string, runId: string): Promise<ValidationState> {
  const raw = await fs.readFile(statePath(stateDir, runId), "utf-8");
  return JSON.parse(raw) as ValidationState;
}


/** Return the most recent (or active) run. Used by `monitor` + `verify` if no --run-id given. */
export async function findActiveRun(stateDir: string): Promise<string | null> {
  let entries;
  try { entries = await fs.readdir(stateDir); }
  catch { return null; }

  const runDirs = entries.filter(e => e.startsWith("run_"));
  if (runDirs.length === 0) return null;

  // Newest first by mtime
  const stats = await Promise.all(
    runDirs.map(async d => ({
      d,
      mtime: (await fs.stat(path.join(stateDir, d))).mtimeMs,
    })),
  );
  stats.sort((a, b) => b.mtime - a.mtime);
  return stats[0]!.d.replace(/^run_/, "");
}


/**
 * Compute hour-offset for a state snapshot. Returns the elapsed hours since
 * `state.startedAt`.
 */
export function hourOffsetNow(state: ValidationState): number {
  const elapsedMs = Date.now() - new Date(state.startedAt).getTime();
  return elapsedMs / 3_600_000;
}
