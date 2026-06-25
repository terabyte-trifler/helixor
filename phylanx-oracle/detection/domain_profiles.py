"""
detection/domain_profiles.py — behavioural signatures of declared domains.

An agent DECLARES a domain at registration ("defi-trading", "lending",
"nft-marketplace", ...). The consistency dimension's domain classifier
checks whether the agent's OBSERVED behaviour matches the expected
behavioural profile of that declared domain — a "lending agent" suddenly
doing NFT mints is inconsistent with its declaration.

A "domain profile" is the EXPECTED transaction-type distribution for that
domain, over the five txtype categories Phylanx's feature extractor uses:

    (swap, lend, stake, transfer, other)

These profiles are deliberately COARSE and HONEST. They are not learned
from data here — they are hand-specified priors describing the dominant
transaction shape of each domain. They are structured as data so they can
be refined (or replaced with learned profiles) by editing this one file.
The domain classifier measures the Jensen-Shannon divergence between an
agent's observed txtype-mix and its declared domain's profile.

An UNKNOWN or unspecified domain → the classifier abstains (no penalty):
Phylanx does not punish an agent for operating in a domain Phylanx has no
profile for.
"""

from __future__ import annotations

from types import MappingProxyType


# Txtype category order — MUST match FeatureVector's txtype group order:
#   txtype_swap_frac, txtype_lend_frac, txtype_stake_frac,
#   txtype_transfer_frac, txtype_other_frac
TXTYPE_ORDER: tuple[str, ...] = ("swap", "lend", "stake", "transfer", "other")


# Each profile is an expected (swap, lend, stake, transfer, other) mix.
# The values are priors — dominant-shape descriptions, not precise forecasts.
_DOMAIN_PROFILES: dict[str, tuple[float, float, float, float, float]] = {
    # A trading agent is swap-dominated.
    "defi-trading":    (0.75, 0.05, 0.05, 0.10, 0.05),
    # A lending agent is lend-dominated.
    "lending":         (0.10, 0.70, 0.05, 0.10, 0.05),
    # A staking agent is stake-dominated.
    "staking":         (0.05, 0.05, 0.75, 0.10, 0.05),
    # An NFT-marketplace agent is mostly "other" (mints/bids/listings are
    # not swap/lend/stake/transfer) with some transfers.
    "nft-marketplace": (0.10, 0.02, 0.03, 0.25, 0.60),
    # A payments / treasury agent is transfer-dominated.
    "payments":        (0.05, 0.05, 0.05, 0.80, 0.05),
    # A liquidity-provision agent splits swaps and stakes (LP deposits).
    "liquidity":       (0.45, 0.10, 0.35, 0.05, 0.05),
    # A yield aggregator moves across lend / stake / swap.
    "yield":           (0.30, 0.35, 0.30, 0.03, 0.02),
}

# Frozen public view.
DOMAIN_PROFILES = MappingProxyType(_DOMAIN_PROFILES)


def known_domains() -> tuple[str, ...]:
    """All domains with a declared behavioural profile."""
    return tuple(sorted(DOMAIN_PROFILES))


def domain_profile(domain: str) -> tuple[float, float, float, float, float] | None:
    """
    The expected txtype distribution for `domain`, or None if Phylanx has
    no profile for it (the classifier then abstains — no penalty).

    Lookup is case-insensitive and tolerant of '_' / ' ' vs '-'.
    """
    if not domain:
        return None
    key = domain.strip().lower().replace("_", "-").replace(" ", "-")
    return DOMAIN_PROFILES.get(key)
