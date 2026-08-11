"""Concrete funnel filters (ADR-014).

Each filter implements ``depwolf.domain.funnel.Filter``. The reasons and
details match the original ``prioritize_cves`` output 1:1 so reports and exit
codes stay byte-compatible.
"""

from __future__ import annotations

from depwolf.domain.funnel import FilterContext
from depwolf.domain.match import asset_matches, row_os
from depwolf.domain.risk import calculate_risk


def _best_risk_result(ctx: FilterContext):
    """The risk result of the highest-risk row in ctx (or None)."""
    best = None
    for r in ctx.rows:
        risk = calculate_risk(cvss=r.cvss_score, epss=r.epss_score, kev=r.kev, evidence_count=1)
        if best is None or risk.score > best.score:
            best = risk
    return best


def _best_risk(ctx: FilterContext) -> float:
    best = _best_risk_result(ctx)
    return best.score if best else 0.0


def _severity_of(ctx: FilterContext) -> str | None:
    best = _best_risk_result(ctx)
    return best.severity if best else None


class InvalidIdFilter:
    name = "invalid_id"

    def apply(self, ctx: FilterContext) -> None:
        if not ctx.cve_id.startswith("CVE-"):
            ctx.reason = self.name
            ctx.detail = "Not a valid CVE ID format"


class NotFoundFilter:
    name = "not_found"

    def apply(self, ctx: FilterContext) -> None:
        if not ctx.rows:
            ctx.reason = self.name
            ctx.detail = "Not present in the NVD index"


class OSMismatchFilter:
    name = "os_mismatch"

    def apply(self, ctx: FilterContext) -> None:
        if ctx.os_filter not in ("linux", "windows"):
            return
        os_rows = [r for r in ctx.rows if row_os(r) is None or row_os(r) == ctx.os_filter]
        if not os_rows:
            ctx.reason = self.name
            ctx.detail = f"Only affects the wrong OS (targeting {ctx.os_filter})"
            ctx.severity = None
            return
        ctx.rows = os_rows


class IgnoredFilter:
    name = "ignored"

    def apply(self, ctx: FilterContext) -> None:
        if ctx.cve_id not in ctx.ignored:
            return
        ctx.reason = self.name
        ctx.detail = "Dismissed by user"
        ctx.risk_score = _best_risk(ctx)
        ctx.severity = _severity_of(ctx)


class NotInStackFilter:
    name = "not_in_stack"

    def apply(self, ctx: FilterContext) -> None:
        if not ctx.assets:
            return
        affected = [a.product for a in ctx.assets if any(asset_matches(a, r) for r in ctx.rows)]
        if not affected:
            ctx.reason = self.name
            ctx.detail = "Affected product/version is not present in your stack"
            ctx.risk_score = _best_risk(ctx)
            ctx.severity = _severity_of(ctx)
            return
        ctx.affected_assets = affected
        ctx.matched_row = next(
            (r for r in ctx.rows if any(asset_matches(a, r) for a in ctx.assets)),
            None,
        )


class LowRiskFilter:
    name = "low_risk"

    def apply(self, ctx: FilterContext) -> None:
        ctx.risk_score = _best_risk(ctx)
        ctx.severity = _severity_of(ctx)
        if ctx.risk_score < 35:
            ctx.reason = self.name
            ctx.detail = "Risk score below action threshold"


def default_funnel_filters() -> list:
    return [
        InvalidIdFilter(),
        NotFoundFilter(),
        OSMismatchFilter(),
        IgnoredFilter(),
        NotInStackFilter(),
        LowRiskFilter(),
    ]
