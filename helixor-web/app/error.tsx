"use client";

import { useEffect } from "react";
import Link from "next/link";

export default function ErrorBoundary({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[helixor/web] root error:", error);
  }, [error]);

  return (
    <div className="mx-auto max-w-2xl px-6 lg:px-10 py-32 text-center">
      <span className="eyebrow">Something broke</span>
      <h1 className="mt-4 text-display-2 text-ink-12 tracking-tight">
        We couldn't reach the cluster.
      </h1>
      <p className="mt-6 text-[15px] text-ink-9 leading-relaxed">
        This is on us, not you. Try again or head home.
      </p>
      <div className="mt-10 flex items-center justify-center gap-3">
        <button
          onClick={reset}
          className="h-10 px-5 rounded-full bg-ink-12 text-ink-0 text-[13px] font-medium hover:bg-ink-11 transition-colors"
        >
          Try again
        </button>
        <Link
          href="/"
          className="h-10 px-5 rounded-full border border-ink-4 inline-flex items-center text-[13px] text-ink-10 hover:text-ink-12 hover:border-ink-6"
        >
          Home
        </Link>
      </div>
      {error.digest && (
        <p className="mt-12 font-mono text-[11px] text-ink-7">
          error id: {error.digest}
        </p>
      )}
    </div>
  );
}
