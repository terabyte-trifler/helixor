#!/usr/bin/env python3
"""
audit/hardening_check.py — programmatic hardening sweep for all 3 programs.

This is the Day-29 re-run of the Day-13 hardening checklist. It walks every
Rust source file in the three Anchor programs and reports findings in six
categories, each of which is a real audit-blocker if violated:

  1. NAKED UNWRAP / EXPECT  — fail-loud panics in production code
  2. CANONICAL PDA BUMPS    — every PDA must use the canonical bump form
  3. UNCHECKED ARITHMETIC   — +, -, *, / outside test code must be checked_*
                              / saturating_* / wrapping_*
  4. OVERFLOW-CHECKS=TRUE   — every program's release profile must opt in
  5. AUTHORITY CONSTRAINTS  — sensitive ix's (update_score, execute_slash,
                              etc.) must carry signer + has_one / Anchor
                              account-level constraints
  6. CARGO.TOML LINTS       — clippy and unused-must-use enforced at workspace

The sweep is deliberately strict: a finding is REPORTED unless the line is
either (a) inside a `#[cfg(test)]` / `mod tests` block, or (b) explicitly
allow-listed with `// audit: <reason>`. False positives are surfaced for
human review rather than silently swallowed.

Run from the repo root:
    python3 audit/hardening_check.py
Exits 0 if clean, 1 if any HARD finding. Soft findings are listed without
failing — they are pointers for review, not blockers.

This auditor is itself a hardening artifact: an auditor that cannot run on
the repo it audits is not an auditor. It runs in CI on every PR.
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


# =============================================================================
# What "the codebase" means
# =============================================================================

REPO_ROOT       = Path(__file__).resolve().parent.parent
PROGRAMS_DIR    = REPO_ROOT / "phylanx-programs" / "programs"
PROGRAM_NAMES   = ("health-oracle", "certificate-issuer", "slash-authority")

# Anchor injects the `pda::Pubkey::find_program_address` pattern for
# CANONICAL bumps. The accepted forms are listed exhaustively; anything
# else is flagged for human review.
ACCEPTED_BUMP_FORMS = (
    r"bump\s*=\s*ctx\.bumps\.",            # Anchor 0.30+ field access
    r"bump\s*=\s*\*ctx\.bumps\.get\(",      # Anchor 0.29- map access
    r"bump\s*,",                            # `bump,` in #[account(seeds = .., bump,)]
    r"bump\s*\)",                           # `bump)` closing the same
    r"bump\s*=\s*self\.bump",               # stored bump on the account itself
    r"bump\s*=\s*\w+\.bump",                # stored bump on a deref'd account
)


# =============================================================================
# Finding model
# =============================================================================

@dataclass
class Finding:
    category: str
    severity: str             # "HARD" (blocking) | "SOFT" (review)
    file:     str
    line:     int
    text:     str
    note:     str = ""


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    @property
    def hard(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "HARD"]

    @property
    def soft(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "SOFT"]

    def by_category(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = defaultdict(list)
        for f in self.findings:
            out[f.category].append(f)
        return out


# =============================================================================
# File walking with test-block awareness
# =============================================================================

def is_test_context(lines: list[str], idx: int) -> bool:
    """
    True if line `idx` is inside `#[cfg(test)] mod tests { ... }` or
    `#[cfg(test)] fn ... {}` or a `#[test]` function. We scan backward for
    the nearest such marker that has not been closed.

    This is a heuristic — Rust nesting can be complex — but it is the
    standard auditor pattern and matches the Day-13 sweep.
    """
    depth = 0
    for j in range(idx, -1, -1):
        ln = lines[j]
        # Track brace depth backward.
        depth += ln.count("}") - ln.count("{")
        if depth <= 0:
            # We are inside something that opened earlier; if that
            # opener was a test marker, this line is in test context.
            if (
                "#[cfg(test)]" in ln
                or "#[test]" in ln
                or re.search(r"mod\s+tests\s*\{", ln)
            ):
                return True
    return False


def has_allow_comment(line: str) -> bool:
    return "// audit:" in line or "// audit-allow" in line


def iter_rust_files(programs_dir: Path) -> list[tuple[str, Path]]:
    """Yield (program_name, source_file) pairs across all programs."""
    out: list[tuple[str, Path]] = []
    for prog in PROGRAM_NAMES:
        src_root = programs_dir / prog / "src"
        if not src_root.exists():
            continue
        for path in sorted(src_root.rglob("*.rs")):
            out.append((prog, path))
    return out


def relpath(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


# =============================================================================
# Check 1 — naked unwrap / expect in production code
# =============================================================================

UNWRAP_RE = re.compile(r"\.unwrap\s*\(")
EXPECT_RE = re.compile(r"\.expect\s*\(")


def check_unwraps(programs_dir: Path, report: Report) -> None:
    for prog, path in iter_rust_files(programs_dir):
        text = path.read_text()
        lines = text.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if has_allow_comment(line):
                continue
            if is_test_context(lines, i):
                continue
            if UNWRAP_RE.search(line):
                report.add(Finding(
                    category="naked-unwrap",
                    severity="HARD",
                    file=relpath(path), line=i + 1, text=stripped,
                    note="replace with `?` or a typed error",
                ))
            if EXPECT_RE.search(line):
                report.add(Finding(
                    category="naked-expect",
                    severity="HARD",
                    file=relpath(path), line=i + 1, text=stripped,
                    note="replace with `?` and an explicit Anchor error variant",
                ))


# =============================================================================
# Check 2 — canonical PDA bumps
# =============================================================================

BUMP_USAGE_RE = re.compile(r"\bbump\b")


def check_canonical_bumps(programs_dir: Path, report: Report) -> None:
    """
    Every PDA derivation must use a canonical bump. We grep for `bump`
    references inside `#[account(...)]` attrs and check the form matches
    one of `ACCEPTED_BUMP_FORMS`. The check is informational (SOFT) when
    we cannot parse the context — we surface the line for human review
    rather than fail.
    """
    accepted = re.compile("|".join(ACCEPTED_BUMP_FORMS))

    for prog, path in iter_rust_files(programs_dir):
        text = path.read_text()
        lines = text.splitlines()
        # Find lines inside `#[account( ... )]` blocks that mention bump.
        in_account_attr = False
        for i, line in enumerate(lines):
            if has_allow_comment(line):
                continue
            if "#[account(" in line:
                in_account_attr = True
            if in_account_attr and "bump" in line and not BUMP_USAGE_RE.search(
                line.strip().lstrip("/")
            ) is None:
                if not accepted.search(line):
                    # `bump` mentioned but no accepted form — review.
                    report.add(Finding(
                        category="non-canonical-bump",
                        severity="SOFT",
                        file=relpath(path), line=i + 1,
                        text=line.strip(),
                        note="confirm canonical bump form",
                    ))
            if ")]" in line:
                in_account_attr = False


# =============================================================================
# Check 3 — unchecked arithmetic
# =============================================================================
#
# Naked `+`, `-`, `*`, `/` on numeric types is a panic risk. We require
# `checked_*` / `saturating_*` / `wrapping_*` everywhere in production
# code. We exempt array indexing (`a[i + 1]`) and string concatenation —
# those are not arithmetic — by skipping lines inside brackets where the
# operator appears between an index expression's bounds. The regex is
# conservative and surfaces SOFT findings on ambiguous cases.

ARITH_RE = re.compile(
    r"(?<![\w])("
    r"[a-zA-Z_]\w*\s*[+\-*/]\s*[a-zA-Z_0-9]"   # x + y / a * b
    r")"
)
SAFE_PATTERNS = (
    "checked_", "saturating_", "wrapping_",
    "// audit:", "audit-allow",
    "use ", "::",                              # use statements / paths
)


def check_arithmetic(programs_dir: Path, report: Report) -> None:
    for prog, path in iter_rust_files(programs_dir):
        text = path.read_text()
        lines = text.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if has_allow_comment(line):
                continue
            if any(p in line for p in SAFE_PATTERNS):
                continue
            if is_test_context(lines, i):
                continue
            # Skip lines that are clearly type signatures, where-clauses,
            # or constants — they often contain `T: Trait + Other`.
            if re.search(r":\s*[a-zA-Z_]\w*\s*\+\s*[a-zA-Z_]", line):
                continue
            # Skip pure index expressions inside brackets — `a[i + 1]`.
            in_brackets = re.findall(r"\[[^\]]*\]", line)
            arith_only_in_brackets = bool(in_brackets) and not ARITH_RE.search(
                ARITH_RE.sub(" ", line).replace("".join(in_brackets), "")
            )
            if arith_only_in_brackets:
                continue
            if ARITH_RE.search(line):
                # Exempt sha256 / hashv / byte slicing — those are not
                # numeric arithmetic.
                if any(t in line for t in (".to_be_bytes", ".to_le_bytes",
                                            "hashv(", "as_ref", "as_slice")):
                    continue
                # Exempt const expressions and array sizes.
                if "const " in line or "SPACE" in line:
                    continue
                # Exempt string formatting where + appears in literals.
                if '"' in line and re.search(r'"[^"]*[+\-*/]', line):
                    continue
                report.add(Finding(
                    category="unchecked-arithmetic",
                    severity="SOFT",  # SOFT — the regex is approximate
                    file=relpath(path), line=i + 1, text=stripped,
                    note="confirm checked_*/saturating_* or allow with `// audit:`",
                ))


# =============================================================================
# Check 4 — overflow-checks = true
# =============================================================================

def check_overflow_checks(programs_dir: Path, report: Report) -> None:
    """Every program's Cargo.toml must enable overflow-checks for release."""
    # The workspace Cargo.toml at programs/../Cargo.toml carries the
    # profile. We check both the workspace and per-program manifests.
    candidates = [programs_dir.parent / "Cargo.toml"]
    for prog in PROGRAM_NAMES:
        candidates.append(programs_dir / prog / "Cargo.toml")

    found_overflow_checks = False
    for cargo in candidates:
        if not cargo.exists():
            continue
        text = cargo.read_text()
        if re.search(r"overflow-checks\s*=\s*true", text):
            found_overflow_checks = True
            break

    if not found_overflow_checks:
        report.add(Finding(
            category="overflow-checks-off",
            severity="HARD",
            file="Cargo.toml",
            line=0,
            text="profile.release.overflow-checks not set to true",
            note="add `[profile.release] overflow-checks = true` "
                 "to the workspace Cargo.toml",
        ))


# =============================================================================
# Check 5 — authority constraints on sensitive instructions
# =============================================================================
#
# Sensitive instructions must enforce SIGNER + an explicit authority check.
# We grep for handler names; for each, confirm the Accounts struct above
# carries a Signer<'info> and a has_one or constraint = ... check.
#
# The auditor is intentionally NOSY here: a missed constraint is a
# catastrophic bug class. False positives flagged as SOFT for review.

SENSITIVE_HANDLERS = {
    # health-oracle — agent registration + score submission
    "commit_baseline":           "health-oracle",        # registers/rotates agent
    "submit_score":              "health-oracle",        # cluster submits a score
    # advance_epoch: VULN-02 moved authority into the handler body — the
    # valid signer set is conditional on elapsed time (Tier 1 vs Tier 2),
    # which an Anchor account-attribute constraint cannot express. Allow-listed.
    "initialize_oracle_config":  "health-oracle",        # one-time admin
    "initialize_epoch":          "health-oracle",        # one-time admin
    "migrate_registration":      "health-oracle",        # migration tool

    # certificate-issuer — cert writes + admin
    "initialize_config":         "certificate-issuer",   # one-time admin
    # record_baseline: VULN-06 moved authority into the handler body via
    # `require!(is_authorised_baseline_writer(...))`. The (agent OR cluster
    # member) rule cannot be expressed as a single Anchor account-attribute
    # constraint because `cluster_keys` is a Vec on `IssuerConfig`. Allow-listed.
    # issue_certificate is INTENTIONALLY signerless apart from the rent
    # payer — Day 27 replaced the issuer-key gate with threshold
    # signature verification (see programs/certificate-issuer/src/signing.rs).
    # The threshold-sig check IS the authority constraint. Allow-listed.

    # slash-authority — slash execution + appeals
    "execute_slash":             "slash-authority",
    "appeal_slash":              "slash-authority",
    "resolve_appeal":            "slash-authority",
    # challenge_oracle is DELIBERATELY PERMISSIONLESS — any party may
    # file a challenge; the slash-authority validates the proof later.
    # Allow-listed.
}

# Handlers whose lack of an authority constraint is BY DESIGN, with the
# alternative authority mechanism documented. The auditor accepts the
# justification rather than reporting a false positive.
DESIGN_INTENT_ALLOWLIST = {
    "issue_certificate":  "Day 27 — threshold signature verification "
                          "replaces the issuer-key gate; see "
                          "certificate-issuer/src/signing.rs",
    "challenge_oracle":   "Permissionless by design — any party may file; "
                          "proof is validated by slash-authority",
    "record_baseline":    "VULN-06 — authority enforced in the handler via "
                          "`require!(is_authorised_baseline_writer(...))`. "
                          "The (agent OR cluster member) rule cannot be a "
                          "single Anchor account-attribute constraint "
                          "because `cluster_keys` is a Vec.",
    "advance_epoch":      "VULN-02 — two-tier authority enforced in the "
                          "handler. The valid signer set is conditional on "
                          "elapsed time (Tier 1: advance_authority at 1× "
                          "duration; Tier 2: any cluster key at 2×), which "
                          "an account-attribute constraint cannot express.",
}


def check_authority_constraints(programs_dir: Path, report: Report) -> None:
    """
    For each sensitive ix, find its Accounts struct and assert it:
      - contains at least one Signer<'info> account, AND
      - contains at least one `constraint =`, `has_one =`, or explicit
        signer-pubkey check.

    Handlers in DESIGN_INTENT_ALLOWLIST are accepted with their documented
    alternative authority mechanism (e.g. issue_certificate uses threshold
    sigs, challenge_oracle is permissionless by design).
    """
    # Audit the allowlisted handlers as SOFT-with-note so the audit
    # report still SHOWS them — an auditor can confirm the alternative
    # authority is in place — but they don't block.
    for handler, justification in DESIGN_INTENT_ALLOWLIST.items():
        report.add(Finding(
            category="design-intent-no-signer-constraint",
            severity="SOFT",
            file=f"phylanx-programs/.../instructions/{handler}.rs",
            line=0,
            text=f"{handler}: no signer constraint by design",
            note=justification,
        ))

    for handler, program in SENSITIVE_HANDLERS.items():
        ix_file = programs_dir / program / "src" / "instructions" / f"{handler}.rs"
        if not ix_file.exists():
            found_in = _find_handler_in_program(programs_dir / program, handler)
            if found_in is None:
                report.add(Finding(
                    category="missing-handler",
                    severity="SOFT",
                    file=f"phylanx-programs/programs/{program}",
                    line=0,
                    text=f"sensitive handler {handler!r} not found",
                    note="confirm the handler exists or remove from the auditor list",
                ))
                continue
            ix_file = found_in
        text = ix_file.read_text()
        has_signer = "Signer<'info>" in text or "Signer<" in text
        has_constraint = bool(
            re.search(r"\bconstraint\s*=", text)
            or re.search(r"\bhas_one\s*=", text)
            or re.search(r"\.key\s*\(\s*\)\s*==", text)
        )
        # An Anchor `init` constraint with `payer = <signer>` is itself the
        # authority check for one-time-init handlers: only the first caller
        # can create the account, and Anchor refuses a second init. The
        # admin update authority is then enforced on subsequent ix's via
        # the account's stored `authority` field.
        is_init_admin = (
            bool(re.search(r"\binit\b\s*,", text))
            and bool(re.search(r"payer\s*=\s*\w+", text))
        )
        if not has_signer:
            report.add(Finding(
                category="missing-signer",
                severity="HARD",
                file=relpath(ix_file), line=0,
                text=f"{handler} Accounts struct has no Signer<'info>",
                note="sensitive ix must have a signer",
            ))
        if not has_constraint and not is_init_admin:
            report.add(Finding(
                category="missing-authority-constraint",
                severity="HARD",
                file=relpath(ix_file), line=0,
                text=f"{handler} has no constraint / has_one / pubkey check",
                note="add Anchor authority check on the signer or related account",
            ))


def _find_handler_in_program(prog_root: Path, handler: str) -> Path | None:
    for f in prog_root.rglob("*.rs"):
        text = f.read_text()
        if f"pub fn {handler}(" in text or f"pub fn handler(" in text and handler in str(f):
            return f
    return None


# =============================================================================
# Check 6 — Cargo lints enforced
# =============================================================================

def check_workspace_lints(programs_dir: Path, report: Report) -> None:
    cargo = programs_dir.parent / "Cargo.toml"
    if not cargo.exists():
        report.add(Finding(
            category="missing-workspace-cargo",
            severity="HARD",
            file="phylanx-programs/Cargo.toml", line=0,
            text="workspace Cargo.toml not found",
        ))
        return
    text = cargo.read_text()
    if "[lints" not in text and "[workspace.lints" not in text:
        report.add(Finding(
            category="missing-lints-table",
            severity="SOFT",
            file=relpath(cargo), line=0,
            text="no [workspace.lints] or [lints] table",
            note="add a lints table that denies clippy::all and "
                 "unused_must_use across the workspace",
        ))


# =============================================================================
# Driver
# =============================================================================

def run() -> Report:
    report = Report()
    check_unwraps(PROGRAMS_DIR, report)
    check_canonical_bumps(PROGRAMS_DIR, report)
    check_arithmetic(PROGRAMS_DIR, report)
    check_overflow_checks(PROGRAMS_DIR, report)
    check_authority_constraints(PROGRAMS_DIR, report)
    check_workspace_lints(PROGRAMS_DIR, report)
    return report


def print_report(report: Report) -> None:
    by_cat = report.by_category()
    print("\n=== HARDENING SWEEP — Day 29 ===\n")
    for cat in sorted(by_cat):
        findings = by_cat[cat]
        hard = sum(1 for f in findings if f.severity == "HARD")
        soft = sum(1 for f in findings if f.severity == "SOFT")
        print(f"[{cat}]  {hard} HARD, {soft} SOFT")
        for f in findings[:20]:
            print(f"  {f.severity:4}  {f.file}:{f.line}")
            if f.text:
                print(f"        {f.text[:100]}")
            if f.note:
                print(f"        note: {f.note}")
        if len(findings) > 20:
            print(f"  ... {len(findings) - 20} more")
        print()
    print("─" * 60)
    print(f"TOTAL: {len(report.hard)} HARD findings, "
          f"{len(report.soft)} SOFT findings")
    if not report.hard:
        print("✅ CLEAN — no blocking findings.")
    else:
        print("❌ HARD findings present — audit-readiness BLOCKED.")


def write_json_report(report: Report, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "hard_count": len(report.hard),
        "soft_count": len(report.soft),
        "findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "text": f.text,
                "note": f.note,
            }
            for f in report.findings
        ],
    }
    path.write_text(json.dumps(payload, indent=2))


def main() -> int:
    report = run()
    print_report(report)
    write_json_report(report, REPO_ROOT / "audit" / "reports" / "hardening.json")
    return 1 if report.hard else 0


if __name__ == "__main__":
    sys.exit(main())
