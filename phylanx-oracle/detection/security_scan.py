"""
detection/security_scan.py — the Day-9 attack-pattern scanner.

    scan(transactions, metadata) -> list[SecuritySignal]

Applies the `PATTERN_LIBRARY` to a window of transactions plus agent
`ScanMetadata`. Three matching mechanisms:

  REGEX / SEMANTIC patterns run over TEXTUAL fields — transaction memos,
  log messages, and the agent's declared metadata text.

  STRUCTURAL patterns run over the SHAPE of the transaction window —
  program IDs, counterparties, fees, value flows.

Pure + deterministic: regex, token-Jaccard, and structural predicates are
all stable across machines (the Phase-4 BFT rule). No embeddings, no ML.

The scanner is built CONSERVATIVELY. The Day-9 done-when is two-sided:
known attacks flagged AND benign traffic producing zero flags. The second
half is the hard half — a security layer that cries wolf is worse than
none — so every structural predicate requires a real threshold, and the
textual patterns are anchored to phrasings implausible in benign Solana
memo traffic.
"""

from __future__ import annotations

from collections.abc import Sequence

from detection._security_match import (
    best_template_similarity,
    containment_score,
    normalise_text,
    programs_outside_declared,
    regex_search,
    tokenize,
)
from detection.security_patterns import (
    PATTERN_LIBRARY,
    AttackPattern,
)
from detection.security_types import (
    DetectionMethod,
    ScanMetadata,
    SecuritySignal,
    Severity,
)
from features.types import Transaction


# =============================================================================
# Structural thresholds — every one documented; this is what keeps the
# false-positive rate at zero on benign traffic.
# =============================================================================

# HLX-SEC-013 — confused deputy: at least this fraction of txs must invoke
# an off-manifest program before we emit (one stray tx is not a signal).
OFF_MANIFEST_MIN_FRACTION   = 0.10
# HLX-SEC-014 — new-counterparty outflow: net SOL out to a never-seen
# counterparty exceeding this magnitude (lamports).
NEW_CP_OUTFLOW_LAMPORTS     = 100_000_000           # 0.1 SOL
# HLX-SEC-015 — authority-change burst: this many authority/approve-type
# instructions to a single new delegate within the window.
AUTHORITY_BURST_COUNT       = 3
# HLX-SEC-017 — off-domain activity fraction.
OFF_DOMAIN_MIN_FRACTION     = 0.25
# HLX-SEC-018 — program-variety expansion: distinct programs exceeding this
# multiple of the historical norm (norm passed via metadata in Day 10;
# Day-9 uses an absolute floor as a placeholder).
PROGRAM_VARIETY_FLOOR       = 12
# HLX-SEC-019 — fee-drain: this many txs with priority fee above the floor
# AND near-zero net value.
FEE_DRAIN_MIN_COUNT         = 5
FEE_DRAIN_PRIORITY_FLOOR    = 50_000               # lamports priority fee
FEE_DRAIN_VALUE_CEILING     = 10_000               # |sol_change| below this = "no value"
# HLX-SEC-020 — dust storm: this many near-zero-value transfers.
DUST_MIN_COUNT              = 10
DUST_VALUE_CEILING          = 1_000                # lamports
# HLX-SEC-022 — new-program value move: a program seen this few times or
# fewer that nonetheless moves material value.
NEW_PROGRAM_MAX_SEEN        = 2
NEW_PROGRAM_VALUE_FLOOR     = 50_000_000           # 0.05 SOL
# HLX-SEC-029 — rapid drain: cumulative outflow exceeding this fraction of
# total inflow within the window.
RAPID_DRAIN_OUTFLOW_RATIO   = 0.90
# HLX-SEC-030 — memo-channel abuse: fraction of txs carrying a large memo.
MEMO_ABUSE_MIN_FRACTION     = 0.50
MEMO_LARGE_CHARS            = 120


# =============================================================================
# scan()
# =============================================================================

def scan(
    transactions: Sequence[Transaction],
    metadata:     ScanMetadata,
    *,
    denylisted_programs: frozenset[str] = frozenset(),
) -> list[SecuritySignal]:
    """
    Scan a window of transactions for attack patterns.

    Returns a list of `SecuritySignal`s, one per (pattern, evidence) match,
    ordered deterministically by (severity desc, pattern_id, tx_signature).

    `denylisted_programs` is the curated known-malicious program set used by
    HLX-SEC-021; empty by default.

    Pure + deterministic.
    """
    signals: list[SecuritySignal] = []

    # ── Textual scan: REGEX + SEMANTIC patterns over all text fields ────────
    texts = _collect_texts(transactions, metadata)
    for pattern in PATTERN_LIBRARY:
        if pattern.method is DetectionMethod.REGEX:
            signals.extend(_scan_regex(pattern, texts))
        elif pattern.method is DetectionMethod.SEMANTIC:
            signals.extend(_scan_semantic(pattern, texts))

    # ── Structural scan: one handler per structural_key ─────────────────────
    signals.extend(_scan_structural(transactions, metadata, denylisted_programs))

    # Deterministic ordering: severity desc, then pattern id, then tx sig.
    signals.sort(key=lambda s: (-int(s.severity), s.pattern_id, s.tx_signature))
    return signals


# =============================================================================
# Textual scanning
# =============================================================================

class _TextField:
    """A piece of scannable text + where it came from (for evidence)."""
    __slots__ = ("raw", "normalised", "tokens", "tx_signature", "source")

    def __init__(self, raw: str, tx_signature: str, source: str) -> None:
        self.raw = raw
        self.normalised = normalise_text(raw)
        self.tokens = tokenize(self.normalised)
        self.tx_signature = tx_signature
        self.source = source


def _collect_texts(
    transactions: Sequence[Transaction],
    metadata:     ScanMetadata,
) -> list[_TextField]:
    """Gather every scannable text field: tx memos/logs + agent metadata."""
    fields: list[_TextField] = []

    # Agent-level declared text (tool manifest, description).
    if metadata.declared_text:
        fields.append(_TextField(metadata.declared_text, "", "declared_text"))

    # Per-transaction text. The Transaction type carries `memo` and `logs`
    # if present; we read them defensively (older records may lack them).
    for tx in transactions:
        memo = getattr(tx, "memo", "") or ""
        if memo:
            fields.append(_TextField(memo, tx.signature, "memo"))
        logs = getattr(tx, "logs", ()) or ()
        for log_line in logs:
            if log_line:
                fields.append(_TextField(log_line, tx.signature, "log"))
    return fields


def _scan_regex(pattern: AttackPattern, texts: list[_TextField]) -> list[SecuritySignal]:
    """Run a REGEX pattern over every text field."""
    out: list[SecuritySignal] = []
    for field in texts:
        match = regex_search(pattern.regex, field.normalised)
        if match is not None:
            out.append(SecuritySignal(
                pattern_id=pattern.id,
                category=pattern.category,
                severity=pattern.severity,
                method=DetectionMethod.REGEX,
                # A regex match is high-confidence by construction.
                confidence=0.95,
                evidence=f"{field.source}: matched '{_redact(match)}'",
                tx_signature=field.tx_signature,
            ))
    return out


def _scan_semantic(pattern: AttackPattern, texts: list[_TextField]) -> list[SecuritySignal]:
    """
    Run a SEMANTIC pattern: token-Jaccard + containment vs known-bad templates.
    Fires when EITHER similarity measure clears the pattern's threshold.
    """
    out: list[SecuritySignal] = []
    for field in texts:
        if not field.tokens:
            continue
        jac = best_template_similarity(field.tokens, pattern.semantic_templates)
        # Containment: best fraction of any single template's tokens present.
        cont = max(
            (containment_score(field.tokens, t) for t in pattern.semantic_templates),
            default=0.0,
        )
        score = max(jac, cont)
        if score >= pattern.semantic_threshold:
            out.append(SecuritySignal(
                pattern_id=pattern.id,
                category=pattern.category,
                severity=pattern.severity,
                method=DetectionMethod.SEMANTIC,
                # Confidence scales with how far past threshold we are.
                confidence=_semantic_confidence(score, pattern.semantic_threshold),
                evidence=f"{field.source}: semantic match (similarity {score:.2f})",
                tx_signature=field.tx_signature,
            ))
    return out


def _semantic_confidence(score: float, threshold: float) -> float:
    """
    Map a similarity score (>= threshold) to a confidence in [0.5, 0.95].
    At threshold → 0.5; at similarity 1.0 → 0.95.
    """
    if threshold >= 1.0:
        return 0.5
    frac = (score - threshold) / (1.0 - threshold)
    return max(0.5, min(0.95, 0.5 + 0.45 * frac))


# =============================================================================
# Structural scanning
# =============================================================================

def _scan_structural(
    transactions:        Sequence[Transaction],
    metadata:            ScanMetadata,
    denylisted_programs: frozenset[str],
) -> list[SecuritySignal]:
    """
    Run all STRUCTURAL patterns. Each `structural_key` has a dedicated
    detector below; a key with no detector is skipped (forward-compatible).
    """
    out: list[SecuritySignal] = []
    if not transactions:
        return out

    handlers = {
        "programs_outside_declared":  _detect_off_manifest,
        "denylisted_program":         _detect_denylisted,
        "fee_drain_burst":            _detect_fee_drain,
        "dust_storm":                 _detect_dust_storm,
        "rapid_balance_drain":        _detect_rapid_drain,
        "memo_channel_abuse":         _detect_memo_abuse,
        "new_program_value_move":     _detect_new_program_value,
        "authority_change_burst":     _detect_authority_burst,
        "program_variety_expansion":  _detect_program_variety,
        # new_counterparty_outflow / off_domain_activity require Day-10's
        # baseline/domain context — registered here, no-op until then.
    }
    from detection.security_patterns import PATTERN_LIBRARY as _LIB
    for pattern in _LIB:
        if pattern.method not in (DetectionMethod.STRUCTURAL, DetectionMethod.COMPOSITE):
            continue
        handler = handlers.get(pattern.structural_key)
        if handler is None:
            continue
        sig = handler(pattern, transactions, metadata, denylisted_programs)
        if sig is not None:
            out.append(sig)
    return out


def _detect_off_manifest(pattern, transactions, metadata, _deny):
    """HLX-SEC-013: a meaningful fraction of txs invoke off-manifest programs."""
    if not metadata.declared_programs:
        return None
    off = 0
    example = ""
    for tx in transactions:
        outside = programs_outside_declared(tx.program_ids, metadata.declared_programs)
        if outside:
            off += 1
            if not example:
                example = sorted(outside)[0]
    fraction = off / len(transactions)
    if fraction >= OFF_MANIFEST_MIN_FRACTION:
        return SecuritySignal(
            pattern_id=pattern.id, category=pattern.category,
            severity=pattern.severity, method=DetectionMethod.STRUCTURAL,
            confidence=min(0.95, 0.5 + fraction),
            evidence=f"{off}/{len(transactions)} txs invoked off-manifest "
                     f"program(s) e.g. {_redact(example)}",
        )
    return None


def _detect_denylisted(pattern, transactions, _metadata, denylisted):
    """HLX-SEC-021: any tx invokes a denylisted program."""
    if not denylisted:
        return None
    for tx in transactions:
        hits = [p for p in tx.program_ids if p in denylisted]
        if hits:
            return SecuritySignal(
                pattern_id=pattern.id, category=pattern.category,
                severity=pattern.severity, method=DetectionMethod.STRUCTURAL,
                confidence=0.98,
                evidence=f"invoked denylisted program {_redact(hits[0])}",
                tx_signature=tx.signature,
            )
    return None


def _detect_fee_drain(pattern, transactions, _metadata, _deny):
    """HLX-SEC-019: burst of high-priority-fee txs with no economic counterpart."""
    drain = [
        tx for tx in transactions
        if getattr(tx, "priority_fee", 0) >= FEE_DRAIN_PRIORITY_FLOOR
        and abs(getattr(tx, "sol_change", 0)) <= FEE_DRAIN_VALUE_CEILING
    ]
    if len(drain) >= FEE_DRAIN_MIN_COUNT:
        return SecuritySignal(
            pattern_id=pattern.id, category=pattern.category,
            severity=pattern.severity, method=DetectionMethod.STRUCTURAL,
            confidence=min(0.9, 0.5 + 0.05 * len(drain)),
            evidence=f"{len(drain)} high-priority-fee txs with near-zero value",
        )
    return None


def _detect_dust_storm(pattern, transactions, _metadata, _deny):
    """HLX-SEC-020: burst of near-zero-value transfers."""
    dust = [
        tx for tx in transactions
        if 0 < abs(getattr(tx, "sol_change", 0)) <= DUST_VALUE_CEILING
    ]
    if len(dust) >= DUST_MIN_COUNT:
        return SecuritySignal(
            pattern_id=pattern.id, category=pattern.category,
            severity=pattern.severity, method=DetectionMethod.STRUCTURAL,
            confidence=min(0.85, 0.5 + 0.02 * len(dust)),
            evidence=f"{len(dust)} dust-value transfers in window",
        )
    return None


def _detect_rapid_drain(pattern, transactions, _metadata, _deny):
    """HLX-SEC-029: near-total outflow within the window."""
    inflow  = sum(c for c in (getattr(t, "sol_change", 0) for t in transactions) if c > 0)
    outflow = -sum(c for c in (getattr(t, "sol_change", 0) for t in transactions) if c < 0)
    if inflow <= 0:
        return None
    ratio = outflow / inflow
    if ratio >= RAPID_DRAIN_OUTFLOW_RATIO and outflow >= NEW_CP_OUTFLOW_LAMPORTS:
        return SecuritySignal(
            pattern_id=pattern.id, category=pattern.category,
            severity=pattern.severity, method=DetectionMethod.STRUCTURAL,
            confidence=min(0.9, ratio),
            evidence=f"outflow {ratio:.0%} of inflow within window",
        )
    return None


def _detect_memo_abuse(pattern, transactions, _metadata, _deny):
    """HLX-SEC-030: unusually high fraction of txs carry large memos."""
    large = sum(
        1 for tx in transactions
        if len(getattr(tx, "memo", "") or "") >= MEMO_LARGE_CHARS
    )
    fraction = large / len(transactions)
    if fraction >= MEMO_ABUSE_MIN_FRACTION:
        return SecuritySignal(
            pattern_id=pattern.id, category=pattern.category,
            severity=pattern.severity, method=DetectionMethod.STRUCTURAL,
            confidence=min(0.8, 0.4 + fraction),
            evidence=f"{large}/{len(transactions)} txs carry large memo payloads",
        )
    return None


def _detect_new_program_value(pattern, transactions, _metadata, _deny):
    """HLX-SEC-022: a barely-seen program handles material value."""
    counts: dict[str, int] = {}
    for tx in transactions:
        for p in tx.program_ids:
            counts[p] = counts.get(p, 0) + 1
    for tx in transactions:
        if abs(getattr(tx, "sol_change", 0)) < NEW_PROGRAM_VALUE_FLOOR:
            continue
        for p in tx.program_ids:
            if counts.get(p, 0) <= NEW_PROGRAM_MAX_SEEN:
                return SecuritySignal(
                    pattern_id=pattern.id, category=pattern.category,
                    severity=pattern.severity, method=DetectionMethod.STRUCTURAL,
                    confidence=0.6,
                    evidence=f"rarely-seen program {_redact(p)} moved material value",
                    tx_signature=tx.signature,
                )
    return None


def _detect_authority_burst(pattern, transactions, _metadata, _deny):
    """
    HLX-SEC-015: a burst of authority/approve instructions.

    Day-9 uses a simple proxy — txs whose memo/logs reference an authority
    change. The precise instruction-decode lands with Day-10's richer
    transaction model; this placeholder is conservative (high count needed).
    """
    auth_terms = ("setauthority", "approve", "delegate", "set_authority")
    hits = 0
    for tx in transactions:
        blob = (getattr(tx, "memo", "") or "").lower()
        logs = getattr(tx, "logs", ()) or ()
        blob += " ".join(logs).lower()
        if any(term in blob for term in auth_terms):
            hits += 1
    if hits >= AUTHORITY_BURST_COUNT:
        return SecuritySignal(
            pattern_id=pattern.id, category=pattern.category,
            severity=pattern.severity, method=DetectionMethod.STRUCTURAL,
            confidence=min(0.8, 0.4 + 0.1 * hits),
            evidence=f"{hits} authority/approve-type operations in window",
        )
    return None


def _detect_program_variety(pattern, transactions, _metadata, _deny):
    """HLX-SEC-018: distinct-program count exceeds an absolute floor."""
    distinct = set()
    for tx in transactions:
        distinct.update(tx.program_ids)
    if len(distinct) > PROGRAM_VARIETY_FLOOR:
        return SecuritySignal(
            pattern_id=pattern.id, category=pattern.category,
            severity=pattern.severity, method=DetectionMethod.STRUCTURAL,
            confidence=0.55,
            evidence=f"{len(distinct)} distinct programs invoked in window",
        )
    return None


# =============================================================================
# Helpers
# =============================================================================

def _redact(text: str, max_len: int = 48) -> str:
    """
    Trim evidence text for safe inclusion in a signal. Never include long
    blobs (could contain a staged payload / secret); truncate with an
    ellipsis.
    """
    t = (text or "").strip()
    if len(t) <= max_len:
        return t
    return t[:max_len] + "..."
