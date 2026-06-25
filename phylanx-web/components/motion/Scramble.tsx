"use client";

import { useEffect, useRef, useState } from "react";

/**
 * Scramble — terminal-native text decode.
 *
 * A mono label resolves left-to-right from protocol glyphs to its final
 * text when scrolled into view. Used sparingly: section pills only.
 * Fixed-width per character (mono upstream), so no layout shift.
 */
const GLYPHS = "▰▱▸◂·:/\\#%@$0123456789";

export function Scramble({ text }: { text: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  const [display, setDisplay] = useState(text);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) return;

    let raf = 0;
    const io = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting) return;
        io.disconnect();
        const t0 = performance.now();
        const dur = 650;
        const tick = (t: number) => {
          const p = Math.min((t - t0) / dur, 1);
          const solved = Math.floor(p * text.length);
          let out = text.slice(0, solved);
          for (let i = solved; i < text.length; i++) {
            const ch = text[i];
            out += ch === " " ? " " : GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
          }
          setDisplay(out);
          if (p < 1) raf = requestAnimationFrame(tick);
          else setDisplay(text);
        };
        raf = requestAnimationFrame(tick);
      },
      { threshold: 0.6 },
    );
    io.observe(el);
    return () => { io.disconnect(); cancelAnimationFrame(raf); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return <span ref={ref}>{display}</span>;
}
