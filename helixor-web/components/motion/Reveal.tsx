"use client";

import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/cn";

/**
 * Reveal — scroll-orchestrated entrance.
 *
 * The hidden state is applied on mount (not in markup), so no-JS visitors
 * and search crawlers always see content. Reduced-motion users get the
 * static page via the CSS guard. `delay` staggers siblings.
 */
export function Reveal({
  children,
  delay = 0,
  className,
}: {
  children: React.ReactNode;
  delay?: number;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<"idle" | "hidden" | "in">("idle");

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) return;                      // stay "idle" — fully static
    // Already in view on mount? Don't hide it — no pop-in above the fold.
    const rect = el.getBoundingClientRect();
    if (rect.top < window.innerHeight * 0.9) return;
    setState("hidden");
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setState("in");
          io.disconnect();
        }
      },
      { threshold: 0.18 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  return (
    <div
      ref={ref}
      className={cn(
        state === "hidden" && "sreveal",
        state === "in" && "sreveal sreveal-in",
        className,
      )}
      style={state === "in" ? { transitionDelay: `${delay}ms` } : undefined}
    >
      {children}
    </div>
  );
}
