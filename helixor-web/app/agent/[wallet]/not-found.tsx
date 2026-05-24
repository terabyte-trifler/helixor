import Link from "next/link";
import { LookupBar } from "@/components/lookup/LookupBar";

export default function NotFound() {
  return (
    <div className="mx-auto max-w-3xl px-6 lg:px-10 py-32 text-center">
      <span className="eyebrow">No score yet</span>
      <h1 className="mt-4 text-display-2 text-ink-12 tracking-tight">
        That agent hasn't been scored.
      </h1>
      <p className="mt-6 text-[16px] text-ink-9 leading-relaxed">
        Helixor only scores agents whose first transaction has been seen by
        at least one cluster epoch. Wallets that have never transacted on
        Solana — or that registered too recently — won't have a cert yet.
      </p>
      <div className="mt-12">
        <LookupBar autoFocus />
      </div>
      <div className="mt-8">
        <Link href="/" className="text-[13px] text-ink-8 hover:text-ink-12">
          Back to home
        </Link>
      </div>
    </div>
  );
}
