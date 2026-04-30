#!/usr/bin/env tsx
// =============================================================================
// scripts/build_report.ts — render a single-page HTML report.
//
// Inputs:  state.json from the run
// Outputs: reports/run_{runId}/report.html
//
// Includes:
//   - Run summary (start, end, duration, runId)
//   - Per-agent timeline (score over time as inline SVG)
//   - Verdict table (PASS/FAIL with reasons)
//   - Epoch latency distribution (p50/p95/max)
//   - Injection log
// =============================================================================

import fs from "node:fs/promises";
import path from "node:path";

import { loadEnv } from "../helpers/env";
import { findActiveRun, loadState, type ValidationState } from "../helpers/state";
import { profileById } from "../profiles/profiles";


function escapeHtml(s: string | null | undefined): string {
  if (s == null) return "";
  return s.replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]!));
}


function buildTimelineSvg(state: ValidationState, agentWallet: string): string {
  const pts = state.snapshots
    .filter(s => s.agentWallet === agentWallet && s.score !== null)
    .sort((a, b) => a.hourOffset - b.hourOffset);
  if (pts.length === 0) return `<svg width="600" height="120"></svg>`;

  const W = 600, H = 120, PAD = 24;
  const xMax = state.durationHours;
  const xScale = (h: number) => PAD + ((W - 2*PAD) * h / Math.max(xMax, 1));
  const yScale = (s: number) => H - PAD - ((H - 2*PAD) * s / 1000);

  const pathD = pts.map((p, i) =>
    `${i === 0 ? "M" : "L"}${xScale(p.hourOffset).toFixed(1)},${yScale(p.score!).toFixed(1)}`,
  ).join(" ");

  const points = pts.map(p => {
    const fill = p.alert === "GREEN" ? "#5ABF5A"
              : p.alert === "YELLOW" ? "#E0B038"
              : p.alert === "RED" ? "#D14747" : "#888";
    return `<circle cx="${xScale(p.hourOffset).toFixed(1)}" cy="${yScale(p.score!).toFixed(1)}" r="3" fill="${fill}" />`;
  }).join("");

  // y-axis tier bands
  const greenY = yScale(700), yellowY = yScale(400);
  const bands = `
    <rect x="${PAD}" y="${PAD}" width="${W-2*PAD}" height="${greenY-PAD}" fill="#5ABF5A" opacity="0.05" />
    <rect x="${PAD}" y="${greenY}" width="${W-2*PAD}" height="${yellowY-greenY}" fill="#E0B038" opacity="0.05" />
    <rect x="${PAD}" y="${yellowY}" width="${W-2*PAD}" height="${H-PAD-yellowY}" fill="#D14747" opacity="0.05" />
  `;

  return `
    <svg viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">
      ${bands}
      <line x1="${PAD}" y1="${H-PAD}" x2="${W-PAD}" y2="${H-PAD}" stroke="#999" stroke-width="0.5"/>
      <line x1="${PAD}" y1="${PAD}" x2="${PAD}" y2="${H-PAD}" stroke="#999" stroke-width="0.5"/>
      <text x="${PAD}" y="${PAD-4}" font-size="9" fill="#666">1000</text>
      <text x="${PAD}" y="${H-PAD+12}" font-size="9" fill="#666">0h</text>
      <text x="${W-PAD-20}" y="${H-PAD+12}" font-size="9" fill="#666">${xMax}h</text>
      <path d="${pathD}" fill="none" stroke="#333" stroke-width="1.2" />
      ${points}
    </svg>
  `;
}


function evaluateAgent(state: ValidationState, agentWallet: string): { passed: boolean; reasons: string[]; final: any } {
  const profile = profileById(state.agents.find(a => a.agentWallet === agentWallet)!.profileId);
  const snaps = state.snapshots
    .filter(s => s.agentWallet === agentWallet && s.score !== null)
    .sort((a, b) => b.hourOffset - a.hourOffset);
  if (snaps.length === 0) return { passed: false, reasons: ["no snapshots"], final: null };
  const final = snaps[0]!;

  const reasons: string[] = [];
  let passed = true;
  const exp = profile.expected;

  if (final.score! < exp.finalScoreRange[0] || final.score! > exp.finalScoreRange[1]) {
    passed = false;
    reasons.push(`score ${final.score} ∉ [${exp.finalScoreRange[0]},${exp.finalScoreRange[1]}]`);
  }
  if (!exp.finalAlertSet.includes(final.alert as any)) {
    passed = false;
    reasons.push(`alert ${final.alert} ∉ {${exp.finalAlertSet.join(",")}}`);
  }
  if (exp.finalAnomalyFlag !== undefined && final.anomalyFlag !== exp.finalAnomalyFlag) {
    passed = false;
    reasons.push(`anomaly_flag ${final.anomalyFlag} ≠ ${exp.finalAnomalyFlag}`);
  }
  if (final.isFresh === false) {
    passed = false;
    reasons.push("is_fresh=false");
  }

  return { passed, reasons, final };
}


function percentiles(values: number[]): { p50: number; p95: number; max: number } {
  if (values.length === 0) return { p50: 0, p95: 0, max: 0 };
  const sorted = [...values].sort((a, b) => a - b);
  const pick = (q: number) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))]!;
  return {
    p50: pick(0.5),
    p95: pick(0.95),
    max: sorted[sorted.length - 1]!,
  };
}


function buildHtml(state: ValidationState): string {
  const finishedAt = state.finishedAt ?? "(in progress)";
  const totalSnapshots = state.snapshots.length;
  const totalEpochs    = state.epochs.length;
  const totalInjections = state.injections.length;

  const epochDurations = state.epochs.map(e => e.durationMs);
  const epochOk        = state.epochs.filter(e => e.exitCode === 0).length;
  const epochP = percentiles(epochDurations);

  const verdicts = state.agents.map(a => ({
    agent: a, ...evaluateAgent(state, a.agentWallet),
  }));
  const allPassed = verdicts.every(v => v.passed);

  const cardRows = state.agents.map(a => {
    const v = verdicts.find(v => v.agent.agentWallet === a.agentWallet)!;
    const mark = v.passed
      ? `<span class="pass">✓ PASS</span>`
      : `<span class="fail">✗ FAIL</span>`;
    const finalCell = v.final
      ? `score <b>${v.final.score}</b> · ${v.final.alert} · anomaly=${v.final.anomalyFlag} · fresh=${v.final.isFresh}`
      : `<i>no snapshot</i>`;
    const reasons = v.reasons.length > 0
      ? `<div class="reasons">${v.reasons.map(r => `<div>· ${escapeHtml(r)}</div>`).join("")}</div>`
      : "";

    const profile = profileById(a.profileId);
    return `
      <section class="agent-card">
        <header>
          <div class="profile-id">${escapeHtml(a.profileId)}</div>
          <div class="verdict">${mark}</div>
        </header>
        <div class="agent-meta">
          <code>${escapeHtml(a.agentWallet)}</code><br/>
          <span class="profile-desc">${escapeHtml(profile.description)}</span>
        </div>
        <div class="timeline">${buildTimelineSvg(state, a.agentWallet)}</div>
        <div class="final-line">${finalCell}</div>
        ${reasons}
      </section>
    `;
  }).join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Helixor Day 14 Validation Report — ${escapeHtml(state.runId)}</title>
<style>
  body { font: 14px system-ui, -apple-system, sans-serif; background: #fafafa; color: #222; max-width: 980px; margin: 24px auto; padding: 0 20px; }
  h1 { margin-bottom: 4px; }
  h1 small { font-weight: 400; color: #888; font-size: 0.6em; }
  .summary { background: #fff; border-radius: 8px; padding: 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 18px; }
  .summary-row { display: flex; gap: 32px; flex-wrap: wrap; margin-top: 8px; }
  .summary-row > div { min-width: 140px; }
  .summary-row b { font-size: 1.4em; }
  .verdict-banner { font-size: 1.6em; padding: 12px 16px; border-radius: 8px; margin: 16px 0 24px; }
  .verdict-banner.pass { background: #d8f0d8; color: #1e6e1e; }
  .verdict-banner.fail { background: #f0d8d8; color: #6e1e1e; }
  .agent-card { background: #fff; border-radius: 8px; padding: 16px 18px; margin-bottom: 14px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
  .agent-card header { display: flex; justify-content: space-between; align-items: baseline; }
  .profile-id { font-family: monospace; font-size: 1.1em; font-weight: 600; }
  .pass { color: #1e6e1e; font-weight: 600; }
  .fail { color: #b8332e; font-weight: 600; }
  .agent-meta { color: #666; font-size: 0.92em; margin: 6px 0 10px; }
  .agent-meta code { background: #f3f3f3; padding: 1px 4px; border-radius: 3px; font-size: 0.92em; }
  .profile-desc { display: block; margin-top: 4px; }
  .timeline svg { width: 100%; max-width: 600px; height: auto; }
  .final-line { margin-top: 8px; font-size: 0.95em; }
  .reasons { margin-top: 4px; font-size: 0.88em; color: #555; line-height: 1.4; }
  table.epoch-table { border-collapse: collapse; width: 100%; font-size: 0.92em; }
  table.epoch-table th, table.epoch-table td { padding: 4px 8px; border-bottom: 1px solid #eee; text-align: left; }
  .small { font-size: 0.85em; color: #888; }
</style>
</head>
<body>

<h1>Helixor — Day 14 Validation <small>runId ${escapeHtml(state.runId)}</small></h1>

<div class="verdict-banner ${allPassed ? "pass" : "fail"}">
  ${allPassed
    ? `✓ All ${verdicts.length} agents PASS validation.`
    : `✗ ${verdicts.filter(v => !v.passed).length}/${verdicts.length} agents FAILED.`}
</div>

<section class="summary">
  <div class="small">Run window</div>
  <div><b>${escapeHtml(state.startedAt)}</b> &nbsp;→&nbsp; <b>${escapeHtml(finishedAt)}</b></div>
  <div class="summary-row">
    <div><div class="small">Duration</div><b>${state.durationHours}h</b></div>
    <div><div class="small">Snapshot interval</div><b>${state.snapshotIntervalMinutes} min</b></div>
    <div><div class="small">Snapshots</div><b>${totalSnapshots}</b></div>
    <div><div class="small">Epochs</div><b>${totalEpochs}</b> <span class="small">(${epochOk} ok)</span></div>
    <div><div class="small">Injections</div><b>${totalInjections}</b></div>
  </div>
  <div class="summary-row">
    <div><div class="small">Epoch p50</div><b>${(epochP.p50/1000).toFixed(1)}s</b></div>
    <div><div class="small">Epoch p95</div><b>${(epochP.p95/1000).toFixed(1)}s</b></div>
    <div><div class="small">Epoch max</div><b>${(epochP.max/1000).toFixed(1)}s</b></div>
  </div>
</section>

<h2>Per-agent timelines</h2>
${cardRows}

<h2>Epoch log</h2>
<table class="epoch-table">
  <thead><tr><th>t (h)</th><th>started</th><th>duration</th><th>exit</th><th>scores submitted</th></tr></thead>
  <tbody>
    ${state.epochs.map(e => `
      <tr>
        <td>${e.hourOffset.toFixed(2)}</td>
        <td>${escapeHtml(e.startedAt)}</td>
        <td>${(e.durationMs/1000).toFixed(1)}s</td>
        <td>${e.exitCode === 0 ? "<span class='pass'>0</span>" : `<span class='fail'>${e.exitCode}</span>`}</td>
        <td>${e.scoresSubmitted}</td>
      </tr>
    `).join("")}
  </tbody>
</table>

</body>
</html>
`;
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

  const state = await loadState(env.stateDir, runId);
  const html = buildHtml(state);

  const outDir = path.join(env.stateDir, `run_${runId}`);
  await fs.mkdir(outDir, { recursive: true });
  const outFile = path.join(outDir, "report.html");
  await fs.writeFile(outFile, html);

  console.log(`✓ wrote ${outFile}`);
  console.log(`  Open in a browser: file://${path.resolve(outFile)}`);
  return 0;
}


main().then(c => process.exit(c)).catch(err => { console.error(err); process.exit(1); });
