from depwolf.application.filters import (
    IgnoredFilter,
    InvalidIdFilter,
    LowRiskFilter,
    NotFoundFilter,
    NotInStackFilter,
)
from depwolf.domain.funnel import FilterContext, Funnel
from depwolf.infrastructure.store import SqliteIndexStore

ASSETS = [{"product": "log4j", "version": "2.14.1"}]


def _ctx(store, cve_id, assets=ASSETS, ignored=(), os_filter=None):
    return FilterContext(
        cve_id=cve_id,
        rows=store.cve(cve_id),
        assets=[_asset(a) for a in assets],
        os_filter=os_filter,
        ignored=set(ignored),
    )


def _asset(a: dict):
    from depwolf.domain.model import Asset

    return Asset(product=a["product"], version=a["version"])


def _store(index_store) -> SqliteIndexStore:
    return index_store


def test_invalid_id_filter_drops(index_store):
    ctx = _ctx(_store(index_store), "not-a-cve")
    InvalidIdFilter().apply(ctx)
    assert ctx.reason == "invalid_id"
    assert ctx.dropped


def test_not_found_filter_drops(index_store):
    ctx = _ctx(_store(index_store), "CVE-9999-0000")
    NotFoundFilter().apply(ctx)
    assert ctx.reason == "not_found"


def test_ignored_filter_drops(memory_index_store):
    from depwolf.matcher import ignore_cve

    ignore_cve("CVE-2021-44228", store=memory_index_store)
    ctx = _ctx(memory_index_store, "CVE-2021-44228", ignored=("CVE-2021-44228",))
    IgnoredFilter().apply(ctx)
    assert ctx.reason == "ignored"


def test_not_in_stack_filter_drops(index_store):
    ctx = _ctx(_store(index_store), "CVE-2021-44228", assets=[{"product": "otherlib", "version": "1.0"}])
    NotInStackFilter().apply(ctx)
    assert ctx.reason == "not_in_stack"
    assert ctx.detail


def test_not_in_stack_filter_sets_affected(index_store):
    ctx = _ctx(_store(index_store), "CVE-2021-44228")
    NotInStackFilter().apply(ctx)
    assert ctx.reason is None
    assert ctx.affected_assets == ["log4j"]
    assert ctx.matched_row is not None


def test_not_in_stack_version_outside_range(index_store):
    ctx = _ctx(_store(index_store), "CVE-2021-44228", assets=[{"product": "log4j", "version": "3.0"}])
    NotInStackFilter().apply(ctx)
    assert ctx.reason == "not_in_stack"
    assert "outside the vulnerable range" in ctx.detail
    assert ">= 2.0 and < 2.15.0" in ctx.detail
    assert ctx.risk_score is not None and ctx.severity is not None


def test_not_in_stack_product_mismatch(index_store):
    ctx = _ctx(_store(index_store), "CVE-2021-44228", assets=[{"product": "someotherlib", "version": "1.0"}])
    NotInStackFilter().apply(ctx)
    assert ctx.reason == "not_in_stack"
    assert "no matching dependency exists" in ctx.detail


def test_low_risk_filter_drops(index_store):
    ctx = FilterContext(
        cve_id="CVE-X",
        rows=[
            _row(cvss=1.0, epss=0.0, kev=False),
            _row(cvss=2.0, epss=0.1, kev=False),
        ],
        assets=[],
        os_filter=None,
        ignored=set(),
    )
    LowRiskFilter().apply(ctx)
    assert ctx.reason == "low_risk"
    assert ctx.risk_score is not None and ctx.risk_score < 35


def test_low_risk_detail_includes_score_and_threshold(index_store):
    ctx = FilterContext(
        cve_id="CVE-X",
        rows=[_row(cvss=1.0, epss=0.0, kev=False)],
        assets=[],
        os_filter=None,
        ignored=set(),
    )
    LowRiskFilter().apply(ctx)
    assert ctx.reason == "low_risk"
    assert "below the risk threshold 35" in ctx.detail
    assert str(ctx.risk_score) in ctx.detail


def test_funnel_stops_at_first_drop(index_store):
    ctx = _ctx(_store(index_store), "CVE-9999-0000")
    result = Funnel([NotFoundFilter(), LowRiskFilter()]).run(ctx)
    assert result.reason == "not_found"
    assert ctx.risk_score is None  # LowRiskFilter never ran


def test_custom_filter_composable(index_store):
    class CveIdParityFilter:
        name = "odd_cve"

        def apply(self, ctx):
            last = ctx.cve_id.split("-")[-1]
            if int(last) % 2 == 1:
                ctx.reason = self.name
                ctx.detail = "Odd CVE suffix filtered by policy"

    ctx = _ctx(_store(index_store), "CVE-2021-45047")
    Funnel([CveIdParityFilter()]).run(ctx)
    assert ctx.reason == "odd_cve"
    assert ctx.dropped


def _row(*, cvss: float, epss: float, kev: bool):
    from depwolf.domain.model import VulnRange

    return VulnRange(
        cve_id="CVE-X",
        vendor="v",
        product="p",
        version_start_including=None,
        version_start_excluding=None,
        version_end_including=None,
        version_end_excluding="99.0",
        description="",
        cvss_score=cvss,
        cvss_severity="",
        epss_score=epss,
        kev=kev,
        published_date=None,
    )
