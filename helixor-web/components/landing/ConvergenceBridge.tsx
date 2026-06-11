"use client";

import { useEffect, useRef, useState } from "react";

/**
 * ConvergenceBridge — the protocol's shape, scrubbed by scroll.
 *
 * Five branches (five oracle nodes) carry score-dots down bezier curves
 * that merge into a single spine — consensus — which terminates in a
 * certificate assembling itself, layer by layer. The animation progress
 * is bound to scroll position over a tall section with a sticky stage,
 * so the visitor *drives* the consensus by scrolling.
 *
 * Pure math (cubic bezier evaluated in JS), no DOM measurement of paths,
 * no dependencies. Reduced-motion users get the final converged state,
 * static. SSR renders progress 0 — the wide, unconverged field.
 */

const BRANCH_X = [100, 300, 500, 700, 900];
const MERGE_Y = 360;          // where branches meet
const SPINE_END = 520;        // bottom of the consensus spine
const BR = 0.72;              // fraction of a dot's journey spent on the curve

function cubic(a: number, b: number, c: number, d: number, t: number) {
  const u = 1 - t;
  return u * u * u * a + 3 * u * u * t * b + 3 * u * t * t * c + t * t * t * d;
}

/** Position of a dot on branch i at journey-progress t ∈ [0,1]. */
function pointAt(i: number, t: number): { x: number; y: number } {
  const x0 = BRANCH_X[i];
  if (t <= BR) {
    const tb = t / BR;
    return {
      x: cubic(x0, x0, 500, 500, tb),
      y: cubic(40, 220, 250, MERGE_Y, tb),
    };
  }
  const ts = (t - BR) / (1 - BR);
  return { x: 500, y: MERGE_Y + ts * (SPINE_END - MERGE_Y) };
}

const clamp = (v: number, lo = 0, hi = 1) => Math.min(hi, Math.max(lo, v));

export function ConvergenceBridge() {
  const wrapRef = useRef<HTMLDivElement>(null);
  const [p, setP] = useState(0);

  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) {
      setP(1);
      return;
    }
    let raf = 0;
    const onScroll = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        const el = wrapRef.current;
        if (!el) return;
        const rect = el.getBoundingClientRect();
        const span = rect.height - window.innerHeight;
        setP(clamp(-rect.top / Math.max(span, 1)));
      });
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
    };
  }, []);

  // Spine draws in across the middle of the scrub.
  const spineLen = SPINE_END - MERGE_Y;
  const spineDraw = clamp((p - 0.35) / 0.45);

  // Certificate layers assemble near the end.
  const layers = [0.62, 0.74, 0.86].map((th) => clamp((p - th) / 0.1));
  const captionIn = clamp((p - 0.8) / 0.15);
  const labelsOut = 1 - clamp((p - 0.45) / 0.3);

  return (
    <section ref={wrapRef} className="relative h-[170vh] border-b border-ink-3" aria-label="Five oracle node scores converge into one threshold-signed certificate">
      <div className="sticky top-0 h-screen flex items-center justify-center overflow-hidden">
        <div className="w-full max-w-5xl px-6">
          <svg viewBox="0 0 1000 640" className="w-full" aria-hidden>
            {/* Branch curves — the field */}
            {BRANCH_X.map((x0) => (
              <path
                key={x0}
                d={`M ${x0} 40 C ${x0} 220, 500 250, 500 ${MERGE_Y}`}
                fill="none"
                stroke="#2c2624"
                strokeWidth="1.25"
              />
            ))}

            {/* Node labels at the branch heads, fading as consensus forms */}
            {BRANCH_X.map((x0, i) => (
              <text
                key={x0}
                x={x0}
                y={24}
                textAnchor="middle"
                fill="#857b76"
                opacity={labelsOut}
                fontFamily="var(--font-mono)"
                fontSize="11"
                letterSpacing="2"
              >
                NODE-{i}
              </text>
            ))}

            {/* The spine — consensus, drawing in */}
            <line
              x1="500" y1={MERGE_Y} x2="500" y2={SPINE_END}
              stroke="#ff4f2e" strokeWidth="1.5"
              strokeDasharray={spineLen}
              strokeDashoffset={spineLen * (1 - spineDraw)}
            />

            {/* Score dots traveling their branches into the spine */}
            {BRANCH_X.map((_, i) =>
              [0, 1, 2].map((j) => {
                const t = clamp(p * 1.5 - j * 0.16);
                if (t <= 0) return null;
                const pos = pointAt(i, t);
                const onSpine = t > BR;
                const fadeOut = 1 - clamp((t - 0.94) / 0.06);
                return (
                  <circle
                    key={`${i}-${j}`}
                    cx={pos.x}
                    cy={pos.y}
                    r={onSpine ? 3.5 : 4.5}
                    fill={onSpine ? "#ff4f2e" : "#e8e1d8"}
                    opacity={Math.min(t * 8, 1) * fadeOut}
                  />
                );
              }),
            )}

            {/* The certificate, assembling layer by layer */}
            <g>
              <circle cx="500" cy="560" r="34" fill="#ff4f2e" opacity={0.08 * layers[2]} />
              {layers.map((l, k) => (
                <rect
                  key={k}
                  x={472}
                  y={538 + k * 13 + (1 - l) * 8}
                  width="56"
                  height="9"
                  rx="2"
                  fill={k === 2 ? "#ff4f2e" : "#e8e1d8"}
                  opacity={l}
                />
              ))}
              <text
                x="548" y="563"
                fill="#857b76" opacity={layers[2]}
                fontFamily="var(--font-mono)" fontSize="11" letterSpacing="1.5"
              >
                ≥ 3 OF 5 SIGNED
              </text>
            </g>
          </svg>

          {/* Caption — lands with the cert */}
          <div
            className="text-center -mt-2"
            style={{ opacity: captionIn, transform: `translateY(${(1 - captionIn) * 10}px)` }}
          >
            <h2 className="text-display-2 text-ink-12">
              Five scores. One certificate.
            </h2>
            <p className="mt-3 font-mono text-[12px] text-ink-7">
              independent observation in · threshold-signed truth out
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
