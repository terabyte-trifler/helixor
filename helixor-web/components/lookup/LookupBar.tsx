"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { ArrowRight, AlertCircle } from "lucide-react";
import { cn } from "@/lib/cn";
import { FEATURED_AGENTS } from "@/lib/mock";

/**
 * LookupBar — the most important component on the site.
 *
 * A YC partner pastes a wallet (or clicks one of the chips below it) and
 * is taken to /agent/<wallet>. Validation is friendly — Solana wallets are
 * base58 32-44 chars; we accept anything in that range plus the demo
 * agents. Invalid input shakes the input but keeps it editable.
 *
 * Wallet examples below the input are clickable: ZERO friction to "see
 * what this thing does."
 */
export function LookupBar({ autoFocus = false }: { autoFocus?: boolean }) {
  const router = useRouter();
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [shake, setShake] = useState(false);
  const [, startTransition] = useTransition();

  function go(wallet: string) {
    const trimmed = wallet.trim();
    if (!isValidWallet(trimmed)) {
      setError("That doesn't look like a Solana wallet (32–44 base58 chars).");
      setShake(true);
      setTimeout(() => setShake(false), 400);
      return;
    }
    setError(null);
    startTransition(() => {
      router.push(`/agent/${encodeURIComponent(trimmed)}`);
    });
  }

  return (
    <div className="w-full max-w-2xl">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          go(value);
        }}
        className={cn(
          "group flex items-center gap-3",
          "rounded-2xl border border-ink-4",
          "bg-ink-1 px-4 py-3.5",
          "transition-all duration-300",
          "focus-within:border-ink-7 focus-within:bg-ink-2",
          shake && "animate-[shake_0.4s_ease-in-out]",
        )}
      >
        <span className="text-ink-7 select-none font-mono text-[13px] tracking-eyebrow uppercase">
          Wallet
        </span>
        <span className="h-5 w-px bg-ink-4" />
        <input
          type="text"
          value={value}
          autoFocus={autoFocus}
          spellCheck={false}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          onChange={(e) => {
            setValue(e.target.value);
            if (error) setError(null);
          }}
          placeholder="Paste a Solana wallet to score it"
          className={cn(
            "flex-1 bg-transparent outline-none",
            "font-mono text-[15px] text-ink-12 placeholder:text-ink-6",
          )}
          aria-label="Solana wallet address"
        />
        <button
          type="submit"
          className={cn(
            "inline-flex items-center gap-2",
            "h-10 px-4 rounded-xl",
            "bg-ink-12 text-ink-0 text-[13px] font-medium",
            "hover:bg-ink-11 transition-colors",
            "disabled:opacity-50 disabled:cursor-not-allowed",
          )}
          disabled={!value.trim()}
        >
          Score it
          <ArrowRight size={14} strokeWidth={2.25} />
        </button>
      </form>
      {error && (
        <div className="mt-3 flex items-start gap-2 text-[13px] text-tier-red animate-fade-in">
          <AlertCircle size={14} className="mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="mt-6 flex flex-wrap items-center gap-2">
        <span className="font-mono text-[11px] tracking-eyebrow uppercase text-ink-7">
          Try
        </span>
        {FEATURED_AGENTS.map((a) => (
          <button
            key={a.wallet}
            onClick={() => go(a.wallet)}
            className={cn(
              "group inline-flex items-center gap-2",
              "h-7 px-3 rounded-full",
              "border border-ink-4 bg-ink-1",
              "text-[12px] text-ink-9 hover:text-ink-12",
              "hover:border-ink-6 hover:bg-ink-2",
              "transition-colors",
            )}
          >
            <span className={cn("h-1.5 w-1.5 rounded-full", {
              "bg-tier-green":  a.tier === "GREEN",
              "bg-tier-yellow": a.tier === "YELLOW",
              "bg-tier-red":    a.tier === "RED",
            })} />
            {a.label}
          </button>
        ))}
      </div>
    </div>
  );
}

function isValidWallet(s: string): boolean {
  if (FEATURED_AGENTS.some((a) => a.wallet === s)) return true;
  // Solana addresses are base58, 32-44 characters. We accept a slightly
  // wider range for forgiveness (28-50) but enforce base58 alphabet.
  if (!s) return false;
  if (s.length < 28 || s.length > 50) return false;
  return /^[1-9A-HJ-NP-Za-km-z]+$/.test(s);
}
