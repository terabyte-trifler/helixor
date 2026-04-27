// =============================================================================
// tests/pipeline.ts — drive the off-chain pipeline manually for tests.
//
// Why we drive these manually instead of waiting for cron:
//   - baseline_scheduler runs every 10min in production
//   - epoch_runner runs every 1h in production
//
// In CI we can't wait those windows. We invoke the same functions directly
// via subprocess to ensure the pipeline gets exercised the same way.
// =============================================================================

import { spawn } from "node:child_process";

interface RunResult {
  exitCode: number;
  stdout:   string;
  stderr:   string;
  durationMs: number;
}

async function run(
  cmd:  string,
  args: string[],
  opts: { cwd: string; env?: Record<string, string>; timeoutMs?: number } = { cwd: process.cwd() },
): Promise<RunResult> {
  const started = Date.now();
  const timeoutMs = opts.timeoutMs ?? 300_000;

  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: { ...process.env, ...opts.env },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "", stderr = "";
    child.stdout.on("data", (chunk) => stdout += chunk.toString());
    child.stderr.on("data", (chunk) => stderr += chunk.toString());

    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`Timed out after ${timeoutMs}ms: ${cmd} ${args.join(" ")}\n${stderr}`));
    }, timeoutMs);

    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        exitCode: code ?? -1,
        stdout, stderr,
        durationMs: Date.now() - started,
      });
    });
  });
}

const ORACLE_DIR = process.env.HELIXOR_ORACLE_DIR
  ?? "../helixor-oracle";

/**
 * Compute baseline + score for one agent. Bypasses the schedulers.
 * Uses the existing CLIs from Day 5 + Day 6.
 */
export async function recomputeForAgent(agentWallet: string): Promise<RunResult> {
  // Day 5 CLI: --store persists agent_baselines row
  const baseline = await run(
    "python", ["-m", "scripts.compute_baseline", agentWallet, "--store"],
    { cwd: ORACLE_DIR, timeoutMs: 60_000 },
  );
  if (baseline.exitCode !== 0) return baseline;

  // Day 6 CLI: persists to agent_scores
  return await run(
    "python", ["-m", "scripts.compute_score", agentWallet],
    { cwd: ORACLE_DIR, timeoutMs: 60_000 },
  );
}

/**
 * Run one pass of the Day 7 epoch_runner — submits unsynced scores on-chain.
 */
export async function runEpochOnce(): Promise<RunResult> {
  return await run(
    "python", ["-m", "oracle.epoch_runner", "--once"],
    { cwd: ORACLE_DIR, timeoutMs: 300_000 },
  );
}
