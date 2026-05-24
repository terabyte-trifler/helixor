export default function Loading() {
  return (
    <div className="mx-auto max-w-7xl px-6 lg:px-10 py-32 text-center">
      <div className="inline-flex items-center gap-3 text-ink-7">
        <span className="relative inline-flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full rounded-full bg-ok animate-heartbeat" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-ok" />
        </span>
        <span className="font-mono text-[11px] tracking-eyebrow uppercase">
          fetching from cluster…
        </span>
      </div>
    </div>
  );
}
