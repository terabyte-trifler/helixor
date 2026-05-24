import Link from "next/link";

/**
 * Footer — minimal. A column of links, a column of "status," a wordmark
 * echo. No mailing list signup (no list yet to be honest about); no
 * "made with love" garbage.
 */
export function Footer() {
  return (
    <footer className="border-t border-ink-3 mt-32">
      <div className="mx-auto max-w-7xl px-6 lg:px-10 py-16">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-10">
          <div>
            <div className="font-mono text-[13px] text-ink-12">
              helixor <span className="text-ink-7">///</span>
            </div>
            <p className="mt-3 text-[13px] text-ink-8 leading-relaxed max-w-[200px]">
              On-chain trust scoring for autonomous agents on Solana.
            </p>
          </div>

          <FooterCol title="Product">
            <FooterLink href="/network">Network</FooterLink>
            <FooterLink href="/transparency">Transparency</FooterLink>
            <FooterLink href="/docs">Docs</FooterLink>
          </FooterCol>

          <FooterCol title="Protocol">
            <FooterLink href="/docs#architecture">Architecture</FooterLink>
            <FooterLink href="/docs#sdk">SDK</FooterLink>
            <FooterLink href="/docs#api">API</FooterLink>
          </FooterCol>

          <FooterCol title="Status">
            <li className="text-[13px] text-ink-8 flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-ok" />
              5 / 5 nodes
            </li>
            <li className="text-[13px] text-ink-8">
              Epoch <span className="font-mono text-ink-10">287</span>
            </li>
            <li className="text-[13px] text-ink-8">
              <span className="font-mono text-ink-10">14,232</span> agents scored
            </li>
          </FooterCol>
        </div>

        <div className="mt-16 pt-8 border-t border-ink-3 flex flex-wrap items-center justify-between gap-4">
          <p className="text-[12px] text-ink-7">
            © 2026 Helixor. Trust scoring is informational, not investment advice.
          </p>
          <p className="text-[12px] font-mono text-ink-7">
            v0.1.0 · devnet · ed25519
          </p>
        </div>
      </div>
    </footer>
  );
}

function FooterCol({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="eyebrow">{title}</h3>
      <ul className="mt-4 space-y-3">{children}</ul>
    </div>
  );
}

function FooterLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <li>
      <Link
        href={href}
        className="text-[13px] text-ink-9 hover:text-ink-12 transition-colors"
      >
        {children}
      </Link>
    </li>
  );
}
