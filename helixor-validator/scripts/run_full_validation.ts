#!/usr/bin/env tsx
// =============================================================================
// scripts/run_full_validation.ts — run the entire 48h flow (or compressed).
//
// For CI: HELIXOR_VALIDATION_DURATION_HOURS=2 + INTERVAL_MS=600000
//   compresses the validation to 2h with 10min ticks. Useful for nightly CI.
//
// For prod: omit env vars → runs the full 48h.
// =============================================================================

import { spawn } from "node:child_process";

function run(cmd: string, args: string[]): Promise<number> {
  return new Promise(resolve => {
    const c = spawn(cmd, args, { stdio: "inherit" });
    c.on("close", code => resolve(code ?? -1));
  });
}

async function main(): Promise<number> {
  console.log("[run_full_validation] STAGE");
  let r = await run("tsx", ["scripts/stage_validation.ts"]);
  if (r !== 0) return r;

  console.log("\n[run_full_validation] MONITOR");
  r = await run("tsx", ["scripts/monitor_validation.ts"]);
  if (r !== 0) return r;

  console.log("\n[run_full_validation] VERIFY");
  r = await run("tsx", ["scripts/verify_validation.ts"]);
  // verify exit code drives the overall result, but report runs regardless

  console.log("\n[run_full_validation] BUILD REPORT");
  await run("tsx", ["scripts/build_report.ts"]);

  return r;
}


main().then(c => process.exit(c)).catch(err => { console.error(err); process.exit(1); });
