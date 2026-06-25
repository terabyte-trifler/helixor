# phylanx-web

The Phylanx consumer + integrator-facing site. Next.js 15 App Router,
Tailwind v3, Geist fonts, shadcn-style primitives, no third-party
dependencies you don't need.

## What's here

```
phylanx-web/
├── app/                       # Next App Router
│   ├── layout.tsx             # Root: Geist fonts, header, footer, demo banner
│   ├── page.tsx               # Landing: hero + ticker + how it works + integrate
│   ├── agent/[wallet]/        # Per-agent detail (score, history, table)
│   ├── network/               # Live cluster status
│   ├── transparency/          # Public flag + challenge ledger
│   ├── docs/                  # Quickstart
│   ├── loading.tsx            # Global loading
│   ├── error.tsx              # Root error boundary
│   ├── not-found.tsx          # 404
│   └── globals.css            # Tokens, grain, animations
├── components/
│   ├── layout/                # Header, Footer, DemoBanner
│   ├── lookup/                # LookupBar (the hero interaction), MarqueeTicker
│   ├── score/                 # ScoreRing, TierBadge
│   ├── data/                  # HistoryTable
│   └── charts/                # HistorySpark
├── lib/
│   ├── api.ts                 # Fetch client → phylanx-api
│   ├── mock.ts                # Deterministic mock data (demo fallback)
│   ├── cn.ts                  # className composer
│   ├── format.ts              # truncateWallet, formatRelative, …
│   └── tier.ts                # Alert tier helpers
├── types/
│   └── api.ts                 # Wire types mirroring phylanx-api/api/schemas.py
├── tailwind.config.ts         # Design tokens (ink palette, type, motion)
└── next.config.mjs
```

## Running

```bash
npm install
npm run dev          # http://localhost:3000
```

With no env vars set, the site serves deterministic mock data and shows
a "demo data" banner. Point at a real API by setting
`NEXT_PUBLIC_API_URL`.

```bash
cp .env.example .env.local
# edit .env.local → NEXT_PUBLIC_API_URL=https://api.phylanx.xyz
npm run dev
```

## Building

```bash
npm run build
npm run start
```

## Design language

- **Monochrome.** Black canvas, white text, 12-step grayscale (`ink-0`
  through `ink-12`). The only color in the site is the three alert
  tiers (`tier.green` / `tier.yellow` / `tier.red`), the explorer-link
  blue (`chain`), and the cluster-OK green dot (`ok`).
- **Typography.** Geist Sans for prose, Geist Mono for every number,
  wallet, signature, timestamp, label. JetBrains-Mono-discipline.
- **Motion.** Restrained. Score ring fills on mount, hero text reveals
  in sequence, marquee ticker scrolls. No scroll-jacking, no parallax,
  no decorative motion.
- **Density.** High. Real numbers everywhere; no empty heroes.

## Aesthetic commitments (don't violate without thinking)

1. No accent color outside the three tiers. Buttons are white-on-black
   or hairline-bordered. Links in body text are white, not blue.
2. No emoji, no illustrations, no robot mascot.
3. Every page that shows data shows the *time it was computed* and a
   link to the on-chain proof. Phylanx's product is auditability.
4. The lookup bar is on every page where it makes sense (home, agent
   detail). The fastest path to scoring an agent is always one input
   field away.

## Pinned versions

```
next        15.0.3
react       19.0.0
tailwindcss 3.4.14
geist       1.3.1
recharts    2.13.3
lucide-react 0.460.0
```

No "latest" tags. Reproducible builds.

## Deploying

Vercel zero-config: connect the repo, set `NEXT_PUBLIC_API_URL` in the
project's environment variables, deploy. Edge runtime gets you sub-50ms
TTFB; the App Router does the rest.

The site is fully static-renderable except for the agent detail page
and network page (which fetch from the API). Those are React Server
Components — they pre-render on the edge against the API on every
request, no client-side fetching.
