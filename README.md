# Phylanx V2 — Day 32: The Frontend

> Day 31 built the read API. Day 32 builds what a YC partner clicks on:
> a Next.js 15 + Tailwind site with a live agent-lookup widget, a BFT
> cluster status page, and an on-chain ledger for every cert. Monochrome
> by choice; tier-colored only where it matters.

---

## What ships

| Page | What it does | Status |
|------|--------------|--------|
| `/` | Hero with live agent-lookup, marquee ticker, "how it works", live stats, integrate examples | ✅ |
| `/agent/[wallet]` | Score ring, cert details, history chart, on-chain ledger table | ✅ |
| `/network` | 5-node cluster status, last 10 epochs, Byzantine flag log | ✅ |
| `/transparency` | Public strike counter + flag detail rows | ✅ |
| `/docs` | Quickstart with SDK + curl examples + cert schema diagram | ✅ |
| `/_not-found`, `/error`, `/loading` | Graceful UX states | ✅ |
| Production build (`next build`) | All 7 routes, 115 KB First Load JS on landing | ✅ |
| Headless-browser screenshots verified | 6 routes captured + reviewed | ✅ |

---

## The aesthetic commitment

**White on black, no accent.** The user asked for the hardest direction:
no purple-gradient cliché, no fintech blue, no AI-startup teal. The
canvas is `#000`, prose is `#fff`, and the *only* color in the entire
site is:

- the three alert-tier colors (`#34d399` GREEN, `#fbbf24` YELLOW, `#f87171` RED)
- one chain-link blue (`#60a5fa`) for explorer links
- one OK-green (`#22c55e`) for the cluster-heartbeat dot

Everything else — buttons, links, dividers, hover states — is a step on
a hand-tuned 12-stop grayscale (`ink-0` through `ink-12`). The Tailwind
"neutral" palette looks dead on OLED black; these stops are perceptually
even.

Typography is **Geist Sans + Geist Mono**. Inter would have been the
default lazy pick; the frontend-design skill calls it out as too
generic. Geist is Vercel-built, designed for technical products, and
ships with both sans and mono in one family.

A near-invisible 4%-opacity film grain (SVG noise, `mix-blend-mode:
overlay`) lifts OLED black away from feeling like a featureless void.
Tested at four brightness levels.

---

## The one component that earns the demo

`components/lookup/LookupBar.tsx`. A YC partner does one of two things
in the first 5 seconds:

1. Pastes a wallet they care about → routes to `/agent/<wallet>`
2. Clicks one of the four "TRY" chips (Stable arb bot, Yield agent
   recovering, MM strategy drift, Compromised agent) → routes to a
   wallet pre-tuned to tell one of four stories

Either way, in **one tap**, they see a 280px score ring, a tier badge,
five cert detail rows, a 30-epoch history chart, and an on-chain ledger
table. The product is one input field away.

---

## The honest demo mode

`lib/mock.ts` ships deterministic mock data shaped *exactly* like
`phylanx-api/api/schemas.py`. Every Pydantic field, every `_v: 1`
schema-version marker, every `alert_tier_code` integer is mirrored.

When `NEXT_PUBLIC_API_URL` is unset, the site uses the mock layer and
displays a banner at the top:

> **DEMO** · Showing illustrative data shaped exactly like the live API.
> Devnet cluster online; deployed API URL pending.

The banner disappears the moment a real API URL is set. No silent
lying about whether the data is real — exactly the principle Day 30's
mainnet-refusal gate enforces server-side, applied to the client.

---

## The architecture

```
Solana chain
   ↑ writes (3-of-5 BFT cert)
   ├─→ phylanx-indexer (Day 17)  →  TimescaleDB
   │                                    │
   │                                    └─→ phylanx-api (Day 31)   ←── HTTP
   │                                                                    │
   │                                                                    ↓
   │                                                              phylanx-web
   │                                                                  (this)
   │                                                                    │
   │                                                                    ↓
   └─→ phylanx-sdk (Day 19) ────────────────────────────────── browser/server
       (on-chain authoritative reads)                            consumers
```

The frontend depends on `phylanx-api`. It can *also* talk to the SDK
for authoritative reads, but for now stays cached-only — the API + mock
fallback covers every YC-demo path. SDK integration is the next step.

---

## Pinned versions

```
next         15.5.18    (React 19 stable support)
react        19.0.0
tailwindcss  3.4.14     (v4 too new for this risk budget)
geist        1.3.1
recharts     3.8.1      (React 19 peer)
lucide-react 0.460.0
```

Pinned exactly, no `^` or `~`. Reproducible builds, no surprise
upgrades pre-YC.

---

## File structure

```
phylanx-web/
├── app/
│   ├── layout.tsx                # Geist fonts, fixed chrome, demo banner
│   ├── page.tsx                  # Landing
│   ├── agent/[wallet]/
│   │   ├── page.tsx
│   │   └── not-found.tsx
│   ├── network/page.tsx
│   ├── transparency/page.tsx
│   ├── docs/page.tsx
│   ├── error.tsx
│   ├── loading.tsx
│   ├── not-found.tsx
│   └── globals.css               # Tokens, grain, animations, scrollbar
├── components/
│   ├── layout/
│   │   ├── Header.tsx
│   │   ├── Footer.tsx
│   │   └── DemoBanner.tsx
│   ├── lookup/
│   │   ├── LookupBar.tsx         # THE hero interaction
│   │   └── MarqueeTicker.tsx
│   ├── score/
│   │   ├── ScoreRing.tsx         # The visual signature
│   │   └── TierBadge.tsx
│   ├── data/
│   │   └── HistoryTable.tsx
│   └── charts/
│       └── HistorySpark.tsx
├── lib/
│   ├── api.ts                    # Fetch client + mock fallback
│   ├── mock.ts                   # Deterministic per-wallet scores
│   ├── cn.ts
│   ├── format.ts
│   └── tier.ts
├── types/
│   └── api.ts                    # Mirror of phylanx-api/api/schemas.py
├── tailwind.config.ts            # 12-stop ink palette + tier + chain + ok
├── next.config.mjs
├── postcss.config.mjs
├── tsconfig.json
├── package.json                  # All deps pinned
├── .env.example
└── README.md
```

---

## Running

```bash
cd phylanx-web
npm install
npm run dev                 # http://localhost:3000
```

With no env vars set, the site serves demo data with the visible banner.
Point at a real API:

```bash
cp .env.example .env.local
# edit .env.local → NEXT_PUBLIC_API_URL=https://api.phylanx.xyz
npm run dev
```

Production build:

```bash
npm run build               # 7 routes, 115 KB First Load on landing
npm run start
```

Type check:

```bash
npm run typecheck           # clean across the whole app
```

---

## What got verified in this session

1. **`npm install`** with all React 19 peer-dep clashes resolved (motion
   dropped, recharts bumped to v3, next bumped to 15.5).
2. **`npm run typecheck`** clean across every file.
3. **`npm run build`** succeeds — 7 routes, no errors, no warnings of
   substance, 115 KB First Load on the landing.
4. **`npm run start`** serves all 7 routes with `200` in <200 ms.
5. **Headless Chromium screenshots** of every page reviewed for visual
   correctness; two real bugs caught and fixed by *looking at the
   output*:
   - Demo banner stacking with fixed header → wrapped in one fixed
     region with a dynamic-height spacer.
   - Mock data anchored to a fixed 2024 timestamp → "Last computed 730d
     ago" everywhere → floated to live `Date.now()` with a 14m backdate
     for the current cert so it reads "14m ago" not "0s ago."

---

## What deliberately did NOT ship in v1

- **Wallet-connect / registration flow.** The on-chain registration ix
  is real (Day 24); wiring a frontend to it needs devnet integration
  testing and a serious thinking-pass on UX for "your agent's first
  cert." Post-YC.
- **Per-integrator dashboards.** No integrators yet, so no dashboards.
- **Full Solscan / explorer linking.** Today's `href="#"` placeholders;
  swap to `solscan.io/account/<pda>?cluster=mainnet-beta` once
  on-chain PDAs are addressable from the phylanx-sdk.
- **Real auth.** The protocol is permissionless; no accounts needed.

---

## Counts at end of Day 32

| Metric | Count |
|--------|-------|
| Total files (excluding node_modules) | 322 |
| Python LOC                            | 35,717 |
| TypeScript/TSX LOC (frontend)         | 2,916 |
| Rust LOC                              | 5,422 |
| Backend tests passing                 | 1,327 (oracle 1,153 + indexer 95 + api 69 + sdk 10) |
| Frontend routes shipped               | 7 (landing, agent, network, transparency, docs, 404, loading) |
| Production build                      | clean, 115 KB First Load |

---

## The pitch deck visual

If you're putting this in a pitch deck:

- **Slide 1 — Logo / one-line.** "Trust scores that no one can fake."
- **Slide 2 — Screenshot of the landing.** The hero + the 941-GREEN
  showcase + the "TRY" chips. Says everything in one frame.
- **Slide 3 — Screenshot of `/agent/[wallet]`** for the compromised
  agent. Same UI, RED ring, IMMEDIATE RED badge. Shows the contrast.
- **Slide 4 — Screenshot of `/network`** with the "Last 10 epochs"
  table where epoch 284 has `1` Byzantine and `47/50` submitted. Shows
  the protocol caught something real and recovered.
- **Slide 5 — Architecture diagram.** From the README of Day 28.

The site itself is the demo — host it on Vercel under
`phylanx.xyz` and the YC application gets a real URL.

---

*Phylanx V2 · Day 32 complete · the frontend is real · ship-ready.*
