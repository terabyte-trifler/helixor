"use client";

import { useEffect, useRef } from "react";
import { LookupBar } from "@/components/lookup/LookupBar";
import { Pill } from "@/components/ui/Pill";

/**
 * Hero — v3.3, the choreographed entrance.
 *
 * Four motions, one restraint budget:
 *  1. Headline lines rise from behind clip masks with a slight rotational
 *     settle — the split-text reveal, staggered.
 *  2. Sub-copy resolves blur-to-sharp after the headline lands.
 *  3. The /// glyph is cursor-reactive: lerped parallax, depth not gimmick.
 *  4. On scroll-out, content and glyph depart at different rates with a
 *     fade — handing off into the convergence below.
 *
 * Reduced-motion users get the complete static hero: the hidden states
 * live inside the no-preference CSS guard, and no JS handlers attach.
 */

const HERO_MARQUEE = [
  "threshold-signed · 3 of 5",
  "no single scorer",
  "commit-reveal consensus",
  "byzantine nodes get slashed",
  "certificates live on-chain",
  "permissionless reads",
  "verify the math yourself",
];

export function Hero() {
  const sectionRef = useRef<HTMLElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const glyphRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const finePointer = window.matchMedia("(pointer: fine)").matches;

    let raf = 0;
    let tx = 0, ty = 0;        // pointer target
    let cx = 0, cy = 0;        // lerped current
    let depart = 0;            // px scrolled past the hero top

    const tick = () => {
      cx += (tx - cx) * 0.07;
      cy += (ty - cy) * 0.07;
      const g = glyphRef.current;
      if (g) {
        g.style.transform =
          `translate3d(${cx.toFixed(2)}px, calc(-50% + ${(cy + depart * 0.26).toFixed(2)}px), 0)`;
      }
      const c = contentRef.current;
      if (c) {
        c.style.transform = `translate3d(0, ${(depart * 0.16).toFixed(2)}px, 0)`;
        c.style.opacity = String(Math.max(1 - depart / 640, 0).toFixed(3));
      }
      raf = requestAnimationFrame(tick);
    };

    const onMove = (e: PointerEvent) => {
      tx = (e.clientX / window.innerWidth - 0.5) * 26;
      ty = (e.clientY / window.innerHeight - 0.5) * 18;
    };
    const onScroll = () => {
      const r = sectionRef.current?.getBoundingClientRect();
      depart = r ? Math.max(-r.top, 0) : 0;
    };

    raf = requestAnimationFrame(tick);
    if (finePointer) window.addEventListener("pointermove", onMove, { passive: true });
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("scroll", onScroll);
    };
  }, []);

  return (
    <section ref={sectionRef} className="relative bg-accent text-ink-0 overflow-hidden">
      {/* Cursor-reactive tone-on-tone brand watermark — the Signal Shield,
          parallaxed in the ink monochrome against the accent block. */}
      <div
        ref={glyphRef}
        aria-hidden
        className="absolute -right-24 top-1/2 -translate-y-1/2 select-none pointer-events-none hidden lg:block will-change-transform"
      >
        <img
          src="/phylanx-mark-mono-ink.svg"
          alt=""
          className="w-[38rem] opacity-[0.13]"
        />
      </div>

      <div ref={contentRef} className="mx-auto max-w-7xl px-6 lg:px-10 pt-14 pb-16 lg:pt-24 lg:pb-20 relative will-change-transform">
        <div className="max-w-3xl">
          <div className="reveal" style={{ "--d": "0s" } as React.CSSProperties}>
            <Pill dark icon={<span className="h-1.5 w-1.5 rounded-full bg-black/70" aria-hidden />}>
              devnet · 5/5 nodes · epoch 287
            </Pill>
          </div>

          <h1 className="mt-7 text-display-1 lg:text-[5.25rem] lg:leading-[0.98] text-ink-0 font-medium">
            <span className="hero-mask">
              <span className="hero-line" style={{ animationDelay: "0.08s" }}>
                Trust scores
              </span>
            </span>
            <span className="hero-mask">
              <span className="hero-line" style={{ animationDelay: "0.2s" }}>
                no one can fake.
              </span>
            </span>
          </h1>

          <p className="hero-blur mt-7 text-[17px] leading-relaxed text-black/75 max-w-[460px]">
            Every autonomous agent on Solana, scored by five independent
            oracle nodes, signed by at least 3 of 5 cluster keys, anchored
            on-chain. No API calls to trust. No dashboard to believe.
          </p>

          <div className="reveal mt-9" style={{ "--d": "0.55s" } as React.CSSProperties}>
            <LookupBar onAccent />
          </div>
        </div>
      </div>

      {/* Marquee strip on the block's bottom edge */}
      <div className="relative border-t border-black/20 overflow-hidden">
        <div className="flex items-center py-2.5 marquee-track">
          {[...HERO_MARQUEE, ...HERO_MARQUEE].map((s, i) => (
            <span key={i} className="shrink-0 flex items-center px-7 gap-7">
              <span className="font-mono text-[11px] tracking-eyebrow uppercase text-black/70">
                {s}
              </span>
              <span className="h-1 w-1 rounded-full bg-black/40" aria-hidden />
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}
