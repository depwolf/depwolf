"""Concrete funnel filters (ADR-014).

Each filter implements ``depwolf.domain.funnel.Filter``. The reasons and
details match the original ``prioritize_cves`` output 1:1 so reports and exit
codes stay byte-compatible.
"""

from __future__ import annotations

from depwolf.domain.funnel import FilterContext
from depwolf.domain.match import asset_applicability, fuzzy_product_match, row_os
from depwolf.domain.model import Asset, VulnRange
from depwolf.domain.risk import calculate_risk
from depwolf.domain.versions import _normalize, format_range


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


def _asset_verdict(asset: Asset, rows: list[VulnRange]) -> bool | None:
    """Per-asset applicability across all range rows.

    True if any row is YES (known version inside an affected range), None if no
    row is YES but some row cannot be evaluated because the version is unknown,
    False when every row is a definitive NO.
    """
    saw_unknown = False
    for r in rows:
        verdict = asset_applicability(asset, r)
        if verdict is True:
            return True
        if verdict is None:
            saw_unknown = True
    return None if saw_unknown else False


class NotInStackFilter:
    name = "not_in_stack"

    def apply(self, ctx: FilterContext) -> None:
        if not ctx.assets:
            return
        affected: list[str] = []
        unknown: list[str] = []
        for a in ctx.assets:
            verdict = _asset_verdict(a, ctx.rows)
            if verdict is True:
                if a.product not in affected:
                    affected.append(a.product)
            elif verdict is None:
                if a.product not in unknown:
                    unknown.append(a.product)
        if affected:
            ctx.affected_assets = affected
            ctx.matched_row = next(
                (r for r in ctx.rows if any(asset_applicability(a, r) is True for a in ctx.assets)),
                None,
            )
            return
        if unknown:
            ctx.reason = self.name
            ctx.detail = (
                f"Installed version of {unknown[0]} could not be determined — cannot confirm "
                f"{ctx.cve_id} applies."
            )
            ctx.risk_score = _best_risk(ctx)
            ctx.severity = _severity_of(ctx)
            return
        product_ok = [
            a for a in ctx.assets if any(fuzzy_product_match(_normalize(a.product), r.product) for r in ctx.rows)
        ]
        row_products = sorted({r.product for r in ctx.rows if r.product})
        if product_ok:
            a = product_ok[0]
            ranges = " or ".join(
                dict.fromkeys(
                    format_range(
                        r.version_start_including,
                        r.version_start_excluding,
                        r.version_end_including,
                        r.version_end_excluding,
                    )
                    for r in ctx.rows
                    if fuzzy_product_match(_normalize(a.product), r.product)
                )
            )
            ctx.reason = self.name
            ctx.detail = (
                f"Installed version {a.version or 'unknown'} of {a.product} is outside the "
                f"vulnerable range ({ranges})."
            )
        else:
            ctx.reason = self.name
            ctx.detail = (
                f"CVE affects {', '.join(row_products) or 'a product not present in the index'}, "
                "but no matching dependency exists in the project."
            )
        ctx.risk_score = _best_risk(ctx)
        ctx.severity = _severity_of(ctx)


class LowRiskFilter:
    name = "low_risk"

    def apply(self, ctx: FilterContext) -> None:
        ctx.risk_score = _best_risk(ctx)
        ctx.severity = _severity_of(ctx)
        if ctx.risk_score < 35:
            ctx.reason = self.name
            ctx.detail = f"Applicable vulnerability has risk score {ctx.risk_score}, below the risk threshold 35."


def default_funnel_filters() -> list:
    return [
        InvalidIdFilter(),
        NotFoundFilter(),
        OSMismatchFilter(),
        IgnoredFilter(),
        NotInStackFilter(),
        LowRiskFilter(),
    ]
