import { cn } from "@/lib/cn";

/**
 * Pill — the bordered mono section label, shared app-wide.
 *
 * One component so the landing and every internal page speak the same
 * grammar and cannot drift. `dark` is the on-accent variant (hero block);
 * default is accent-on-charcoal.
 */
export function Pill({
  icon,
  children,
  dark = false,
  className,
}: {
  icon: React.ReactNode;
  children: React.ReactNode;
  dark?: boolean;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 h-7 px-3.5 rounded-[3px] border",
        "font-mono text-[11px] tracking-eyebrow uppercase",
        dark ? "border-black/40 text-black/80" : "border-accent/50 text-accent",
        className,
      )}
    >
      {icon}
      {children}
    </span>
  );
}
