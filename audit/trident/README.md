# Trident fuzz harness — Day 29

Trident is the Anchor-aware fuzzer. The local audit gate runs the
generated Trident target directly and asserts zero panics; the same
runner can be dialed up to the full 10,000,000-iteration campaign for a
dedicated audit box.

## What's here

```
audit/trident/
├── Trident.toml                 — audit target metadata
├── run_fuzz.sh                  — one-shot runner with acceptance gates
└── ../../helixor-programs/trident-tests/
    └── fuzz_0/                  — generated Trident target crate
```

## What you need

```
rustup     >= 1.78
solana-cli >= 1.18
anchor-cli  = 0.30.1
trident-cli = 0.7.0
```

## What you run

```bash
bash audit/trident/run_fuzz.sh
HELIXOR_TRIDENT_ITERATIONS=10000000 bash audit/trident/run_fuzz.sh
```

The runner:
1. Builds the workspace with `overflow-checks = true`.
2. Wipes `audit/reports/fuzz_crashes/`.
3. Invokes the generated Trident target with
   `trident fuzz run fuzz_0 --with-exit-code`.
4. Asserts the crash dir is empty, coverage hit every handler, no
   iteration timed out.

The default local gate uses `HELIXOR_TRIDENT_ITERATIONS=1000`, which is
fast enough to run inside `audit/run_all.sh`. The full 10M campaign is
the same command with `HELIXOR_TRIDENT_ITERATIONS=10000000`; expected
runtime on an 8-core audit runner is **4-6 hours**.

## Acceptance gates

- **Default local gate:** 1000 generated Trident iterations with zero
  panics.
- **Full audit campaign:** 10M generated Trident iterations with zero
  panics.
- **Zero crash inputs** persisted in `audit/reports/fuzz_crashes/`.
- **Full handler coverage** in `audit/reports/fuzz_coverage.json`.
- **No iteration over `timeout_seconds`** (DOS-hang detector).

A failure on any gate exits 1 and CI blocks merge.

## Prime targets

The fuzz harness deliberately weighs effort toward the **`issue_certificate`**
ix in `certificate-issuer`, because the Day-27 path parses
**attacker-controlled 144-byte blobs** from the Instructions sysvar. A
single panic in `parse_ed25519_ix` would be a critical CVE.

The fuzz harness generates:
- Arbitrary 0..=300 byte Ed25519 instruction blobs (including truncated,
  oversized, malformed).
- Out-of-bounds offsets in the 16-byte header.
- Cross-instruction reference attempts (must be rejected with
  `CrossInstructionReference`).
- Duplicated signers, non-cluster signers, sigs over wrong digests.
- Boundary threshold cases (threshold = 0, threshold = max, 5+ keys).

If the handler ever panics on one of these, the audit gate fails. The
goal is "every adversarial input returns a *typed Anchor error*."

## What an audit team produces

After `bash audit/trident/run_fuzz.sh` completes cleanly:

- `audit/reports/fuzz_coverage.json` — per-handler hit count
- `audit/reports/fuzz_crashes/` — empty
- A signed audit-log entry referencing the commit SHA and the runtime

The auditor signs off on the Day-29 ticket once these three artefacts are
in place. CI sustains the gate on every commit; manual reruns happen
quarterly or after any cert-issuer change.
