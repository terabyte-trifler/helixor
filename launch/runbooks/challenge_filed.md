# Runbook — challenge_oracle filed

**Severity:** Page.
**Trigger:** `ChallengeOracleFiled` — a node reached 3 Byzantine strikes
and the watchdog filed an on-chain challenge.

## What's happening

The accused node is now eligible for slashing. The challenge cites a
specific (agent, epoch, score, median) tuple — recorded in the
`OracleChallenge` PDA — proving the deviation.

This is the **last step** of the Byzantine response: 3 epochs of
deviation triggered the on-chain action. If the deviations were genuine,
slashing is correct. If they were a detection regression, this is a bug
and the challenge needs to be resolved as not-upheld.

## Triage

1. Read the prior `byzantine_flag.md` postmortems for this node — were
   the 3 flags investigated? Are they consistent (same root cause)?
2. Fetch the on-chain challenge:
   ```bash
   curl -s "http://api/challenges?node=$NODE" | jq '.challenges[-1]'
   ```
3. Confirm the slash hasn't auto-executed — the slash-authority has a
   dispute window (Day 21) during which the node can `appeal_slash`.

## Decision tree

- **Deviations were genuine:** let the slash execute when the dispute
  window closes. Document the incident, including which keypair (so
  the operator doesn't reuse a slashed key).
- **Deviations were a detector regression:** the accused node files
  `appeal_slash`; the slash authority resolves the appeal as upholding
  the node. The bug in detection gets a separate P0 ticket.

## When to wake the lead

Always. A challenge_oracle is a money event.
