"use client";

import {
  Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis, ReferenceLine,
} from "recharts";
import type { HistoryEntry } from "@/types/api";

/**
 * HistorySpark — score history chart for the agent detail page.
 *
 * Monochrome: white area gradient, white line. Reference lines at 400
 * (YELLOW threshold) and 800 (GREEN threshold) in the tier colors —
 * the only chromatic moments. No legend, no chart title; the surrounding
 * page provides context.
 */
export function HistorySpark({ entries }: { entries: HistoryEntry[] }) {
  // Recharts wants oldest-first; the API returns newest-first.
  const data = [...entries].reverse().map((e) => ({
    epoch: e.epoch,
    score: e.score,
    computed_at: e.computed_at,
  }));

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 16, right: 0, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id="hxFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%"   stopColor="#ffffff" stopOpacity={0.18} />
              <stop offset="100%" stopColor="#ffffff" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis
            dataKey="epoch"
            tick={{ fill: "#666666", fontSize: 11, fontFamily: "var(--font-geist-mono)" }}
            tickLine={false}
            axisLine={{ stroke: "#1a1a1a" }}
            tickMargin={10}
            interval={4}        // show ~every 5th epoch — readable, uncluttered
          />
          <YAxis
            domain={[0, 1000]}
            ticks={[0, 400, 800, 1000]}
            tick={{ fill: "#666666", fontSize: 11, fontFamily: "var(--font-geist-mono)" }}
            tickLine={false}
            axisLine={false}
            tickMargin={8}
            width={44}          // 36 was too narrow; "1000" needs ~44px
          />
          <ReferenceLine y={400} stroke="#fbbf24" strokeDasharray="2 4" strokeOpacity={0.4} />
          <ReferenceLine y={800} stroke="#34d399" strokeDasharray="2 4" strokeOpacity={0.4} />
          <Tooltip
            cursor={{ stroke: "#262626", strokeWidth: 1 }}
            contentStyle={{
              background: "#0a0a0a",
              border: "1px solid #262626",
              borderRadius: 8,
              fontSize: 12,
              fontFamily: "var(--font-geist-mono)",
              padding: "8px 10px",
            }}
            labelStyle={{ color: "#808080", marginBottom: 4 }}
            itemStyle={{ color: "#ffffff" }}
            formatter={(v) => [`${v}`, "score"] as [string, string]}
            labelFormatter={(l) => `epoch ${l}`}
          />
          <Area
            type="monotone"
            dataKey="score"
            stroke="#ffffff"
            strokeWidth={1.5}
            fill="url(#hxFill)"
            isAnimationActive={true}
            animationDuration={800}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
