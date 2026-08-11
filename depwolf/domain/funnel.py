"""Composable filter funnel (ADR-014).

The AVIP false-positive reduction is an ordered chain of ``Filter`` steps. Each
filter inspects the shared ``FilterContext`` and either lets the finding pass or
drops it by setting ``reason``. Filters are pure orchestrators of domain rules;
the context carries typed data (``VulnRange`` rows, ``Asset`` stack).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from depwolf.domain.model import Asset, VulnRange


class Filter(Protocol):
    """One funnel step. Mutates ``ctx``; ``name`` is the drop reason."""

    name: str

    def apply(self, ctx: FilterContext) -> None: ...


@dataclass
class FilterContext:
    """Shared state threaded through the funnel for one candidate CVE."""

    cve_id: str
    rows: list[VulnRange]
    assets: list[Asset]
    os_filter: str | None
    ignored: set[str]
    reason: str | None = None
    detail: str | None = None
    risk_score: float | None = None
    severity: str | None = None
    matched_row: VulnRange | None = None
    affected_assets: list[str] = field(default_factory=list)

    @property
    def dropped(self) -> bool:
        return self.reason is not None


class Funnel:
    """Ordered filter chain; stops at the first drop."""

    def __init__(self, filters: list[Filter]):
        self.filters = list(filters)

    def run(self, ctx: FilterContext) -> FilterContext:
        for f in self.filters:
            if ctx.dropped:
                break
            f.apply(ctx)
        return ctx
