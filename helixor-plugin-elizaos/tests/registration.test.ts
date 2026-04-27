// =============================================================================
// tests/registration.test.ts — registration helper validation
//
// We don't test against real Solana — just validate input checks and PDA
// derivation. Real submission is exercised by Day 2's TS tests.
// =============================================================================

import { describe, expect, it } from "vitest";

import {
  derivePdas,
  prepareRegistration,
  RegistrationError,
} from "../src/registration";

const VALID_AGENT = "C6EiVB4Tiky14k8mtrK6EJ4FZN54pKCtcJstU7umhtjP";
const VALID_OWNER = "ANoJSqqxqih1kSkjYaRno9YeBMVaYB8gmcPnBdV5NqQJ";

describe("derivePdas", () => {
  it("produces deterministic PDAs", () => {
    const a = derivePdas(VALID_AGENT);
    const b = derivePdas(VALID_AGENT);
    expect(a.registrationPda.toBase58()).toBe(b.registrationPda.toBase58());
    expect(a.escrowVaultPda.toBase58()).toBe(b.escrowVaultPda.toBase58());
  });

  it("produces different PDAs for different agents", () => {
    const a = derivePdas(VALID_AGENT);
    const b = derivePdas(VALID_OWNER);
    expect(a.registrationPda.toBase58()).not.toBe(b.registrationPda.toBase58());
  });
});


describe("prepareRegistration validation", () => {
  const baseArgs = {
    agentWallet: VALID_AGENT,
    ownerWallet: VALID_OWNER,
    name:        "TestAgent",
    rpcUrl:      "https://api.devnet.solana.com",
  };

  it("rejects invalid agent_wallet", async () => {
    await expect(prepareRegistration({ ...baseArgs, agentWallet: "bad" }))
      .rejects.toBeInstanceOf(RegistrationError);
  });

  it("rejects invalid owner_wallet", async () => {
    await expect(prepareRegistration({ ...baseArgs, ownerWallet: "bad" }))
      .rejects.toBeInstanceOf(RegistrationError);
  });

  it("rejects same agent and owner", async () => {
    await expect(prepareRegistration({ ...baseArgs, ownerWallet: VALID_AGENT }))
      .rejects.toThrow(/must differ/);
  });

  it("rejects empty name", async () => {
    await expect(prepareRegistration({ ...baseArgs, name: "" }))
      .rejects.toThrow(/cannot be empty/);
  });

  it("rejects name >64 bytes (UTF-8)", async () => {
    await expect(prepareRegistration({ ...baseArgs, name: "🤖".repeat(17) /* 68 bytes */ }))
      .rejects.toThrow(/64 bytes/);
  });

  it("accepts 64-byte UTF-8 name (boundary)", async () => {
    // 16 emojis = 64 bytes — tx build will reach the RPC step, which we
    // can't easily mock cheaply; ensure validation passes by catching only
    // RPC failures here.
    try {
      await prepareRegistration({ ...baseArgs, name: "🤖".repeat(16) });
    } catch (err) {
      // We allow a non-RegistrationError (network) but not validation errors
      expect(err).not.toBeInstanceOf(RegistrationError);
    }
  });

  it("rejects rpcUrl without scheme", async () => {
    await expect(prepareRegistration({ ...baseArgs, rpcUrl: "api.devnet.solana.com" }))
      .rejects.toThrow(/start with http/);
  });
});
