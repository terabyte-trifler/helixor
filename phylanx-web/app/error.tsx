"use client";

import { useEffect } from "react";
import Link from "next/link";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Pill } from "@/components/ui/Pill";

export default function ErrorBoundary({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[phylanx/web] root error:", error);
  }, [error]);

  return (
    <div className="mx-auto max-w-2xl px-6 lg:px-10 py-32 text-center">
      <div className="flex justify-center">
        <Pill icon={<AlertTriangle size={11} strokeWidth={2.5} />}>Something broke</Pill>
      </div>
      <h1 className="mt-6 text-display-2 text-ink-12 tracking-tight">
        We couldn't reach the cluster.
      </h1>
      <p className="mt-6 text-[15px] text-ink-9 leading-relaxed">
        This is on us, not you. Try again or head home.
      </p>
      <div className="mt-10 flex items-center justify-center gap-3">
        <button
          onClick={reset}
          className="btn-notch inline-flex items-center gap-2 h-11 px-7 bg-accent text-ink-0 font-mono text-[13px] font-medium tracking-wide hover:bg-accent-bright transition-colors"
        >
          <RefreshCw size={13} strokeWidth={2.25} />
          Try again
        </button>
        <Link
          href="/"
          className="h-11 px-6 rounded-full border border-ink-4 inline-flex items-center text-[13px] text-ink-10 hover:text-ink-12 hover:border-ink-6 transition-colors"
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
