// =============================================================================
// helpers/pipeline.ts — invoke Day 5/6/7 Python CLIs.
// =============================================================================

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import type { ValidationEnv } from "./env";


export interface RunResult {
  exitCode:   number;
  stdout:     string;
  stderr:     string;
  durationMs: number;
}

function resolvePython(env: ValidationEnv): string {
  const venvPython = path.join(env.oracleDir, ".venv", "bin", "python");
  return fs.existsSync(venvPython) ? venvPython : "python3";
}


async function run(
  cmd:  string,
  args: string[],
  opts: { cwd: string; timeoutMs?: number },
): Promise<RunResult> {
  const started   = Date.now();
  const timeoutMs = opts.timeoutMs ?? 600_000;

  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => stdout += c.toString());
    child.stderr.on("data", (c) => stderr += c.toString());

    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`Timed out after ${timeoutMs}ms: ${cmd} ${args.join(" ")}`));
    }, timeoutMs);

    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        exitCode:   code ?? -1,
        stdout, stderr,
        durationMs: Date.now() - started,
      });
    });
  });
}


export async function recomputeForAgent(env: ValidationEnv, wallet: string): Promise<RunResult> {
  const python = resolvePython(env);
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


export async function runEpochOnce(env: ValidationEnv): Promise<RunResult> {
  const python = resolvePython(env);
  return await run(
    python, ["-m", "oracle.epoch_runner", "--once"],
    { cwd: env.oracleDir, timeoutMs: 1_200_000 },   // 20min for full epoch
  );
}
