// =============================================================================
// helpers/pipeline.ts — drive baseline + score + epoch_runner from tests.
// Same pattern as Day 10 — invoke real production code paths via subprocess.
// =============================================================================

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import type { IntegrationEnv } from "./env";

export interface RunResult {
  exitCode:   number;
  stdout:     string;
  stderr:     string;
  durationMs: number;
}

async function run(
  cmd:  string,
  args: string[],
  opts: { cwd: string; env?: Record<string, string>; timeoutMs?: number },
): Promise<RunResult> {
  const started   = Date.now();
  const timeoutMs = opts.timeoutMs ?? 120_000;

  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd:   opts.cwd,
      env:   { ...process.env, ...opts.env },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => stdout += c.toString());
    child.stderr.on("data", (c) => stderr += c.toString());

    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(
        `Timed out after ${timeoutMs}ms: ${cmd} ${args.join(" ")}\nstderr: ${stderr.slice(-500)}`,
      ));
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

export async function recomputeForAgent(env: IntegrationEnv, wallet: string): Promise<RunResult> {
  const python = resolveOraclePython(env);
  const baseline = await run(
    python, ["-m", "scripts.compute_baseline", wallet, "--store"],
    { cwd: env.oracleDir, timeoutMs: 60_000 },
  );
  if (baseline.exitCode !== 0) return baseline;
  return await run(
    python, ["-m", "scripts.compute_score", wallet],
    { cwd: env.oracleDir, timeoutMs: 60_000 },
  );
}

export async function runEpochOnce(env: IntegrationEnv): Promise<RunResult> {
  const python = resolveOraclePython(env);
  return await run(
    python, ["-m", "oracle.epoch_runner", "--once"],
    { cwd: env.oracleDir, timeoutMs: 300_000 },
  );
}

export async function runMonitoringOnce(env: IntegrationEnv): Promise<RunResult> {
  const python = resolveOraclePython(env);
  return await run(
    python, ["-m", "monitoring.runner", "--once"],
    { cwd: env.oracleDir, timeoutMs: 60_000 },
  );
}

function resolveOraclePython(env: IntegrationEnv): string {
  const venvPython = path.join(env.oracleDir, ".venv", "bin", "python");
  return fs.existsSync(venvPython) ? venvPython : "python";
}
