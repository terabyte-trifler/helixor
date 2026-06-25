import Link from "next/link";
import { SearchX } from "lucide-react";
import { LookupBar } from "@/components/lookup/LookupBar";
import { Pill } from "@/components/ui/Pill";

export default function NotFound() {
  return (
    <div className="mx-auto max-w-3xl px-6 lg:px-10 py-32 text-center">
      <div className="flex justify-center">
        <Pill icon={<SearchX size={11} strokeWidth={2.5} />}>No score yet</Pill>
      </div>
      <h1 className="mt-6 text-display-2 text-ink-12 tracking-tight">
        That agent hasn't been scored.
      </h1>
      <p className="mt-6 text-[16px] text-ink-9 leading-relaxed max-w-[52ch] mx-auto">
        Phylanx only scores agents whose first transaction has been seen by
        at least one cluster epoch. Wallets that have never transacted on
        Solana — or that registered too recently — won't have a cert yet.
      </p>
      <div className="mt-12 flex justify-center">
        <LookupBar autoFocus />
      </div>
      <div className="mt-10">
        <Link
          href="/"
          className="inline-flex items-center h-10 px-5 rounded-full border border-ink-4 text-[13px] text-ink-10 hover:text-ink-12 hover:border-ink-6 transition-colors"
        >
          Back home
        </Link>
      </div>
    </div>
  );
}
