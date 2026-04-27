import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    testTimeout: 180_000,        // 3min — webhook + scoring loop has natural delay
    hookTimeout: 120_000,        // 2min — setup/teardown
    pool: "forks",               // isolate per-file (Solana clients leak handles)
    poolOptions: { forks: { singleFork: true } },
    reporters: ["verbose"],
  },
});
