"""
diagnosis/remediation.py — actionable remediation codes (u32 bitmask).

A `RemediationCode` value is the structured "what should the operator
do" surface attached to a Phylanx diagnosis certificate. The cert
carries a `remediation_codes: u32` bitmask that consumers can act on
WITHOUT fetching the off-chain DA payload — small, cheap, immediately
actionable.

The default mapping from `FailureMode` bits to a sensible starting set
of `RemediationCode` bits lives in `taxonomy.LABEL_METADATA`. Operator
runbooks may override / extend; the on-chain default is just the
sensible 80-percent-case dispatch.

BIT POSITIONS ARE FROZEN
------------------------
Each name = a single bit position. Reordering or reusing a position
is a breaking on-chain change. Pin tests in
`tests/diagnosis/test_taxonomy_v1.py` enforce every position.
"""

from __future__ import annotations

import enum


class RemediationCode(enum.IntFlag):
    """
    u32 bitmask of structured remediation actions.

    Naming: imperative verb phrases, scoped to a SINGLE responsibility.
    "Pause the agent", "rotate API keys" — not "Investigate".
    """

    # ── Containment (bits 0-7) ────────────────────────────────────────────
    PAUSE_AGENT              = 1 << 0     # stop the agent from taking new actions
    ISOLATE_AGENT            = 1 << 1     # cut the agent off from its peers / tools
    BLOCK_AGENT_PEER         = 1 << 2     # block a specific inbound peer
    QUARANTINE_TOOL_RESULT   = 1 << 3     # hold a tool's last result for review
    RESTART_AGENT_SESSION    = 1 << 4     # bounce the agent's runtime / clear context
    CLEAR_AGENT_MEMORY       = 1 << 5     # purge episodic / vector memory stores
    REVOKE_AGENT_IDENTITY    = 1 << 6     # rotate the agent's signed identity
    ROTATE_API_KEYS          = 1 << 7     # rotate downstream API credentials

    # ── Hardening (bits 8-15) ─────────────────────────────────────────────
    REVIEW_TOOL_PERMISSIONS  = 1 << 8     # audit & tighten tool allow-list
    REDUCE_AUTONOMY          = 1 << 9     # require human-in-the-loop for risky calls
    DECREASE_RATE_LIMITS     = 1 << 10    # tighten the agent's per-minute call budget
    INCREASE_RATE_LIMITS     = 1 << 11    # loosen — paired with capacity bumps only
    PATCH_PROMPT_GUARD       = 1 << 12    # push a new prompt-injection filter
    ENABLE_OUTPUT_FILTER     = 1 << 13    # apply / tighten output content filter
    TIGHTEN_RETRIEVAL_FILTER = 1 << 14    # restrict retrieval source allow-list
    VERIFY_SUPPLY_CHAIN      = 1 << 15    # re-verify pinned package + image hashes

    # ── Recovery (bits 16-23) ─────────────────────────────────────────────
    ROLLBACK_MODEL_VERSION   = 1 << 16    # revert to last-known-good model version
    RUN_FRESH_BASELINE       = 1 << 17    # recompute the agent's behavioural baseline
    SCAN_MEMORY_STORE        = 1 << 18    # diff memory against last-known-good snapshot
    VERIFY_AGENT_IDENTITY    = 1 << 19    # challenge the agent's signed identity

    # ── Escalation (bits 24-31) ───────────────────────────────────────────
    ALERT_OPERATORS          = 1 << 24    # page the on-call channel
    ENGAGE_HUMAN_REVIEW      = 1 << 25    # route the next action through a human
    AUDIT_RECENT_OUTPUTS     = 1 << 26    # diff recent outputs vs distribution
    COLLECT_EVIDENCE         = 1 << 27    # snapshot trace + memory for forensics


# u32 ceiling — the bitmask fits in 32 bits and there is room (bits 20-23 and
# 28-31) for additional remediations without breaking layout. New entries MUST
# claim explicit positions; never auto-pack.
REMEDIATION_MASK_BITS: int = 32
REMEDIATION_MASK_MAX: int = (1 << REMEDIATION_MASK_BITS) - 1
