import Link from "next/link";

export default function NotFound() {
  return (
    <div className="mx-auto max-w-2xl px-6 lg:px-10 py-32 text-center">
      <span className="font-mono text-[11px] tracking-eyebrow uppercase text-ink-7">
        404
      </span>
      <h1 className="mt-4 text-display-1 text-ink-12 tracking-tight">
        Nothing here.
      </h1>
      <p className="mt-6 text-[15px] text-ink-9">
        The page you're looking for either never existed or has moved.
      </p>
      <div className="mt-10">
        <Link
          href="/"
          className="inline-flex h-10 px-5 rounded-full bg-ink-12 text-ink-0 text-[13px] font-medium hover:bg-ink-11"
        >
          Home
        </Link>
      </div>
    </div>
  );
}
