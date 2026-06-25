"use client";

import { useEffect, useRef, useState } from "react";

/**
 * CountUp — a stat value counts to its target when scrolled into view.
 *
 * Parses the leading number out of strings like "3.2ms", "3 of 5", "6.3s",
 * "$0" and animates only the numeric part, preserving prefix/suffix and
 * decimal places. Tabular numerals upstream guarantee zero layout shift.
 */
export function CountUp({ value }: { value: string }) {
  const match = value.match(/^([^0-9]*)([0-9]+(?:\.[0-9]+)?)([\s\S]*)$/);
  const ref = useRef<HTMLSpanElement>(null);
  const [display, setDisplay] = useState(value);

  useEffect(() => {
    if (!match) return;
    const el = ref.current;
    if (!el) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) return;

    const [, prefix, numStr, suffix] = match;
    const target = parseFloat(numStr);
    const decimals = numStr.includes(".") ? numStr.split(".")[1].length : 0;
    let raf = 0;

    const io = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting) return;
        io.disconnect();
        const t0 = performance.now();
        const dur = 1100;
        const tick = (t: number) => {
          const p = Math.min((t - t0) / dur, 1);
          const eased = 1 - Math.pow(1 - p, 3);            // easeOutCubic
          setDisplay(`${prefix}${(target * eased).toFixed(decimals)}${suffix}`);
          if (p < 1) raf = requestAnimationFrame(tick);
        };
        raf = requestAnimationFrame(tick);
      },
      { threshold: 0.5 },
    );
    io.observe(el);
    return () => { io.disconnect(); cancelAnimationFrame(raf); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return <span ref={ref}>{display}</span>;
}
