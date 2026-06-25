import Link from "next/link";
import { cn } from "@/lib/cn";
import { PhylanxMark } from "@/components/brand/PhylanxMark";

/**
 * Header — minimal, fixed-position, hairline-bordered.
 *
 * Logotype is a wordmark, not an icon — "phylanx" set in Geist Mono,
 * lowercase, tight tracking. The /// separator is a deliberate
 * visual signature (echoes the multi-sig threshold) and appears in three
 * other places in the site (footer, hero, network page).
 */
export function Header({ className }: { className?: string }) {
  return (
    <header
      className={cn(
        "backdrop-blur-xl bg-ink-0/70",
        "border-b border-ink-3",
        className,
      )}
    >
      <div className="mx-auto max-w-7xl px-6 lg:px-10">
        <div className="flex h-16 items-center justify-between">
          <Link
            href="/"
            className="group flex items-center gap-2.5"
          >
            <Wordmark />
          </Link>

          <nav className="hidden md:flex items-center gap-1">
            <NavLink href="/network">Network</NavLink>
            <NavLink href="/transparency">Transparency</NavLink>
            <NavLink href="/docs">Docs</NavLink>
          </nav>

          <div className="flex items-center gap-3">
            <a
              href="https://github.com/phylanx"
              target="_blank"
              rel="noopener noreferrer"
              className={cn(
                "hidden sm:inline-flex items-center gap-2",
                "text-[13px] text-ink-9 hover:text-ink-12 transition-colors",
              )}
            >
              GitHub
            </a>
            <Link
              href="/docs"
              className={cn(
                "inline-flex items-center gap-2",
                "h-9 px-4 rounded-full",
                "bg-ink-12 text-ink-0 text-[13px] font-medium",
                "hover:bg-ink-11 transition-colors",
              )}
            >
              Integrate
            </Link>
          </div>
        </div>
      </div>
    </header>
  );
}

function NavLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      className={cn(
        "px-3 py-2 rounded-md",
        "text-[13px] text-ink-9 hover:text-ink-12",
        "transition-colors",
      )}
    >
      {children}
    </Link>
  );
}

/**
 * The lockup: the "Signal Shield" mark + "phylanx" in mono lowercase.
 * A soft vermillion glow breathes behind the mark — the heartbeat that
 * shows "the cluster is live," now carried by the brand mark itself
 * rather than a separate status dot.
 */
function Wordmark() {
  return (
    <span className="flex items-center gap-3">
      <span className="relative inline-flex items-center justify-center">
        <span
          aria-hidden
          className="absolute h-7 w-7 rounded-full bg-accent/25 blur-md animate-heartbeat"
        />
        <PhylanxMark
          size={40}
          className="relative transition-transform duration-300 group-hover:scale-110"
        />
      </span>
      <span className="font-sans text-[20px] font-semibold uppercase tracking-[0.2em] text-ink-12">
        PHYLANX
      </span>
      <span className="hidden sm:inline font-mono text-[11px] uppercase tracking-eyebrow text-ink-7">
        /// devnet
      </span>
    </span>
  );
}
