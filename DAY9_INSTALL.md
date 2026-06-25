# Day 9 Installation

This zip contains:
1. **`phylanx-plugin-elizaos/`** — the new npm package `@elizaos/plugin-phylanx`
2. **`phylanx-oracle/api/routes/registration.py`** — small addition to the
   Day 8 API providing the `POST /agents/prepare-registration` endpoint

## What's in this zip

```
phylanx-plugin-elizaos/         ← NEW package, drop in next to phylanx-sdk/
├── src/
│   ├── index.ts                 (plugin entry + initialize hook)
│   ├── config.ts                (typed settings + validation)
│   ├── state.ts                 (singleton client + telemetry)
│   ├── registration.ts          (build unsigned register_agent tx)
│   ├── actions/
│   │   ├── check_score.ts
│   │   └── prepare_registration.ts
│   ├── evaluators/
│   │   └── trust_gate.ts        (the gate)
│   └── providers/
│       └── score_context.ts     (LLM prompt context injection)
├── tests/                       (50+ tests across config, gate, registration, state)
├── examples/character.json
├── package.json
├── tsconfig.json
├── vitest.config.ts
└── README.md

phylanx-oracle/                 ← addition to Day 8 API
└── api/routes/registration.py
```

## What to do

1. Drop `phylanx-plugin-elizaos/` into the same parent directory as
   `phylanx-sdk/`. They're sibling npm packages.
2. Copy `phylanx-oracle/api/routes/registration.py` into your Day 8
   `phylanx-oracle/api/routes/` directory.
3. Wire the new router in `phylanx-oracle/api/main.py`:
   ```python
   from api.routes import registration as registration_routes
   app.include_router(registration_routes.router, tags=["registration"])
   ```
4. Build + test the plugin:
   ```bash
   cd phylanx-plugin-elizaos
   npm install
   npm test
   npm run build
   ```
5. Use it in any elizaOS character:
   ```typescript
   import { phylanxPlugin } from "@elizaos/plugin-phylanx";
   export default {
     plugins: [phylanxPlugin],
     settings: {
       SOLANA_PUBLIC_KEY: "...",
       PHYLANX_API_URL:   "https://api.phylanx.xyz",
     },
   };
   ```

## Compatibility

- Plugin peer-depends on `@elizaos/core >= 0.1.0`
- Plugin runtime-depends on `@phylanx/client ^0.8.0` (Day 8 SDK)
- Plugin dev-depends on `@solana/web3.js` for tx building only
- Tests use Vitest with mock fetch — no real network needed
