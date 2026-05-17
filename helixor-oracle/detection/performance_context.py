"""
detection/performance_context.py — market context for the performance layer.

The Profit Quality check cross-references an agent's claimed outcomes
against real price action. The price data comes from Pyth feeds — but a
live oracle fetch cannot happen inside a deterministic BFT scorer (Pyth
prices differ millisecond to millisecond; three oracle nodes would
disagree).

So Pyth data is COMMITTED CONTEXT: a `MarketContext` is snapshotted at a
fixed slot when the scoring window is opened, and passed to the
`PerformanceDetector` at construction — exactly as the Sybil graph is
passed to the SecurityDetector (Day 10). Every node scores against the
SAME committed market snapshot, so the result is byte-identical.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from collections.abc import Mapping
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class MarketContext:
    """
    A committed snapshot of market conditions over a scoring window.

    Fields:
      market_return     — the broad market move over the window, as a
                          signed fraction (e.g. -0.12 = the market fell 12%).
                          Sourced from a Pyth aggregate (e.g. a SOL or
                          basket feed) snapshotted at the window's slot.
      asset_returns     — optional per-asset returns (program / mint id →
                          signed fractional return) for agents whose
                          exposure can be attributed to specific assets.
      asset_exposures   — optional per-asset signed exposure weights over
                          the same keys. +1 = long, -1 = short. When this
                          overlaps with asset_returns, Profit Quality uses
                          the weighted per-asset return instead of the broad
                          market_return.
      market_exposure   — the agent's directional exposure to the market,
                          in [-1, 1]: +1 = fully long, -1 = fully short,
                          0 = market-neutral. Defaults to +1 (the common
                          case: a trading agent is net long).
      snapshot_slot     — the Solana slot the Pyth prices were read at;
                          carried for provenance / auditability.

    An empty MarketContext (market_return = 0) is a NEUTRAL market — the
    Profit Quality check then returns its uninformative 0.5 default rather
    than rewarding or punishing.
    """
    market_return:   float = 0.0
    asset_returns:   Mapping[str, float] = field(default_factory=dict)
    asset_exposures: Mapping[str, float] = field(default_factory=dict)
    market_exposure: float = 1.0
    snapshot_slot:   int = 0

    def __post_init__(self) -> None:
        if not math.isfinite(self.market_return):
            raise ValueError(f"market_return must be finite, got {self.market_return}")
        if not (-1.0 <= self.market_exposure <= 1.0):
            raise ValueError(
                f"market_exposure must be in [-1, 1], got {self.market_exposure}"
            )
        for name, mapping in (
            ("asset_returns", self.asset_returns),
            ("asset_exposures", self.asset_exposures),
        ):
            for asset, value in mapping.items():
                if not asset:
                    raise ValueError(f"{name} keys must be non-empty")
                if not math.isfinite(value):
                    raise ValueError(f"{name}[{asset}] must be finite, got {value}")
            if not isinstance(mapping, MappingProxyType):
                object.__setattr__(self, name, MappingProxyType(dict(mapping)))

    @property
    def is_neutral(self) -> bool:
        """A market with no meaningful move — the profit check abstains."""
        return abs(self.effective_market_return) < 1e-9

    @property
    def effective_market_return(self) -> float:
        """
        Deterministic signed market move for this agent's actual exposure.

        If asset-level Pyth returns and signed exposures overlap, use the
        exposure-weighted return:

            sum(asset_return * exposure) / sum(abs(exposure))

        This makes per-mint attribution active today. If no overlap exists,
        fall back to the broad market return.
        """
        common_assets = sorted(set(self.asset_returns) & set(self.asset_exposures))
        weighted_sum = 0.0
        exposure_sum = 0.0
        for asset in common_assets:
            exposure = self.asset_exposures[asset]
            if abs(exposure) <= 1e-12:
                continue
            weighted_sum += self.asset_returns[asset] * exposure
            exposure_sum += abs(exposure)
        if exposure_sum <= 1e-12:
            return self.market_return
        return weighted_sum / exposure_sum


# The default — a neutral market. `default_registry()` builds the
# PerformanceDetector with this; real scoring runs supply a committed snapshot.
NEUTRAL_MARKET = MarketContext()
