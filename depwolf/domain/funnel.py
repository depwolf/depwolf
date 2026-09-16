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
    match_confidence: str | None = None
    # Phase 1 (spec §2/§13/§15/§16): how the finding's product was resolved, and
    # the component identity it resolved through (purl/ecosystem/vendor/product).
    evidence: list[str] = field(default_factory=list)
    component: dict | None = None
    # original stack product -> resolved index product, only when resolution
    # went through a purl/CPE alias (e.g. ``torch`` -> ``pytorch``). Filters
    # evaluate applicability against the resolved product but keep the original
    # dependency name for reporting.
    asset_resolutions: dict[str, str] = field(default_factory=dict)

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
