"""
monitoring/types.py — typed result objects for every check.

Each check returns a CheckResult. The runner aggregates results, decides
which to alert on (via state machine), records SLO samples, and emits
exit codes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


Severity = Literal["info", "warning", "critical"]


@dataclass(frozen=True, slots=True)
class CheckResult:
    """
    One health-check outcome.

    `key` is the canonical alert key for dedup. Use a stable identifier:
        "epoch_stale"           — single global concern
        "agent_score_stale:ABC" — per-agent concerns, with the agent in the key

    `value_ms` is optional — if set, it's recorded as an SLO sample.
    """
    name:       str
    healthy:    bool
    severity:   Severity      = "warning"
    title:      str           = ""
    body:       str           = ""
    key:        str           = ""        # alert dedup key; defaults to `name`
    value_ms:   int | None    = None
    context:    dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # If no explicit alert key, use the check name
        if not self.key:
            object.__setattr__(self, "key", self.name)

    def slo_check_name(self) -> str:
        """The SLO bucket this check contributes to."""
        return self.name


@dataclass(frozen=True, slots=True)
class CheckRunSummary:
    run_id:        str
    started_at:    float
    finished_at:   float
    results:       tuple[CheckResult, ...]
    alerts_fired: int
    alerts_resolved: int

    @property
    def duration_ms(self) -> int:
        return int((self.finished_at - self.started_at) * 1000)

    @property
    def healthy(self) -> bool:
        return all(r.healthy for r in self.results)

    @property
    def critical_count(self) -> int:
        return sum(1 for r in self.results if not r.healthy and r.severity == "critical")
