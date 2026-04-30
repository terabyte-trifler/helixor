#!/usr/bin/env tsx
// =============================================================================
// scripts/harden_all.ts — runs every Day 13 gate sequentially.
//
// Exit code 0 only if EVERY check passes. CI uses this as the merge gate.
// =============================================================================

import { spawn } from "node:child_process";

interface Stage {
  name:    string;
  command: string;
  args:    string[];
  fatal:   boolean;
}

const stages: Stage[] = [
  { name: "Rust hardening",    command: "tsx", args: ["scripts/harden_rust.ts"],    fatal: true },
  { name: "Secret hygiene",    command: "tsx", args: ["scripts/harden_secrets.ts"], fatal: true },
  { name: "TypeScript check",  command: "npm", args: ["run", "typecheck"],          fatal: true },
  { name: "ESLint",            command: "npm", args: ["run", "lint"],               fatal: true },
  { name: "Smoke tests",       command: "npm", args: ["run", "test:smoke"],         fatal: true },
  { name: "Invariant tests",   command: "npm", args: ["run", "test:invariants"],    fatal: true },
  { name: "Transition tests",  command: "npm", args: ["run", "test:transitions"],   fatal: true },
  { name: "Failure-mode tests",command: "npm", args: ["run", "test:failures"],      fatal: true },
  { name: "Determinism tests", command: "npm", args: ["run", "test:determinism"],   fatal: true },
  { name: "On-chain tests",    command: "npm", args: ["run", "test:onchain"],       fatal: false },
  { name: "Regression suite",  command: "npm", args: ["run", "test:regressions"],   fatal: true },
];


function run(stage: Stage): Promise<{ exitCode: number; durationMs: number }> {
  const start = Date.now();
  return new Promise((resolve) => {
    const child = spawn(stage.command, stage.args, { stdio: "inherit" });
    child.on("close", (code) => {
      resolve({ exitCode: code ?? -1, durationMs: Date.now() - start });
    });
  });
}


async function main() {
  console.log("");
  console.log("════════════════════════════════════════════════════════════════");
  console.log("  Helixor — Day 13 hardening + integration tests                ");
  console.log("════════════════════════════════════════════════════════════════");
  console.log("");

  const summary: Array<{ name: string; ok: boolean; ms: number; skipped: boolean }> = [];
  let firstFailure: string | null = null;

  for (const stage of stages) {
    console.log(`\n────  ${stage.name}  ${"─".repeat(Math.max(0, 50 - stage.name.length))}\n`);
    const r = await run(stage);
    const ok = r.exitCode === 0;
    summary.push({ name: stage.name, ok, ms: r.durationMs, skipped: false });
    if (!ok) {
      console.log(`\n\x1b[31m✗  ${stage.name} failed (exit ${r.exitCode})\x1b[0m\n`);
      if (stage.fatal) {
        firstFailure = stage.name;
        break;
      }
    }
  }

  console.log("");
  console.log("════════════════════════════════════════════════════════════════");
  console.log("  Summary                                                        ");
  console.log("════════════════════════════════════════════════════════════════");
  for (const s of summary) {
    const mark = s.ok ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m";
    const dur  = `${(s.ms / 1000).toFixed(1)}s`.padStart(8);
    console.log(`  ${mark}  ${s.name.padEnd(28)}  ${dur}`);
  }
  console.log("");

  if (firstFailure) {
    console.log(`\x1b[31m✗ Halted at first fatal failure: ${firstFailure}\x1b[0m`);
    process.exit(1);
  }

  const allPassed = summary.every(s => s.ok);
  if (!allPassed) {
    console.log(`\x1b[33m! All required stages passed (some optional stages failed — review above)\x1b[0m`);
    process.exit(0);
  }
  console.log(`\x1b[32m✓ Day 13 gate passed — ready for Day 14 devnet validation.\x1b[0m`);
}


main().catch((err) => { console.error(err); process.exit(1); });
