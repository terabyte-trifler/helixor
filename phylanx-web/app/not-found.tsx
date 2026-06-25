import Link from "next/link";
import { ArrowRight, X } from "lucide-react";
import { Pill } from "@/components/ui/Pill";

export default function NotFound() {
  return (
    <div className="mx-auto max-w-2xl px-6 lg:px-10 py-32 text-center">
      <div className="flex justify-center">
        <Pill icon={<X size={11} strokeWidth={2.5} />}>404</Pill>
      </div>
      <h1 className="mt-6 text-display-1 text-ink-12 tracking-tight">
        Nothing here.
      </h1>
      <p className="mt-6 text-[15px] text-ink-9">
        The page you're looking for either never existed or has moved.
      </p>
      <div className="mt-10">
        <Link
          href="/"
          className="btn-notch inline-flex items-center gap-2 h-11 px-7 bg-accent text-ink-0 font-mono text-[13px] font-medium tracking-wide hover:bg-accent-bright transition-colors"
        >
          Back home
          <ArrowRight size={14} strokeWidth={2.25} />
        </Link>
      </div>
    </div>
  );
}
