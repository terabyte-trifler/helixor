import { isMock, networkLabel } from "@/lib/api";
import { cn } from "@/lib/cn";

/**
 * DemoBanner — shows ONLY when the API URL is unset and we're serving
 * mock data. Honest about the demo's state; no silent lying.
 *
 * Disappears the moment NEXT_PUBLIC_API_URL is set to the deployed
 * devnet API.
 */
export function DemoBanner() {
  if (!isMock()) return null;
  return (
    <div className={cn(
      "border-b border-ink-3 bg-ink-3",
      "text-[12px] text-ink-11",
    )}>
      <div className="mx-auto max-w-7xl px-6 lg:px-10 h-9 flex items-center justify-center gap-2.5">
        <span className="font-mono uppercase tracking-eyebrow text-ink-12 font-medium">
          demo
        </span>
        <span className="h-3 w-px bg-ink-6" />
        <span>
          Showing illustrative data shaped exactly like the live API.
          Devnet cluster online; deployed API URL pending.
        </span>
      </div>
    </div>
  );
}
