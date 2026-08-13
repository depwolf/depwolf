"""Phase 6 tests: one-pass batch matching isolates DB connections (ADR-017)."""

from depwolf.application.matcher import match_plan, match_plan_full, prioritize_cves


def test_match_plan_resolves_log4j_in_two_calls(memory_index_store):
    plan = match_plan("log4j 2.14.0", store=memory_index_store)
    assert "CVE-2021-44228" in plan
    assert memory_index_store.open_count <= 2


def test_prioritize_with_plan_does_not_double_query(memory_index_store):
    plan = match_plan("log4j 2.14.0", store=memory_index_store)
    before = memory_index_store.open_count
    result = prioritize_cves(
        ["CVE-2021-44228"],
        "log4j 2.14.0",
        store=memory_index_store,
        plan=plan,
    )
    assert memory_index_store.open_count == before
    assert result["found"] == 1
    assert result["prioritized"][0]["cve_id"] == "CVE-2021-44228"


def test_batch_resolve_many_is_single_connection(memory_index_store):
    store = memory_index_store
    resolved = store.resolve_products_many(["log4j", "apache-log4j", "nonexistent-pkg"])
    assert any(p.product == "log4j" for p in resolved.get("log4j", []))
    assert store.open_count <= 1


def test_cves_for_products_batch(memory_index_store):
    store = memory_index_store
    out = store.cves_for_products([("apache", "log4j")])
    cves = {r.cve_id for r in out[("apache", "log4j")]}
    assert cves == {"CVE-2021-44228", "CVE-2021-45046"}
    assert store.open_count <= 1


def test_backfill_adds_non_stack_cves(memory_index_store):
    plan = match_plan("log4j 2.14.0", store=memory_index_store)
    result = prioritize_cves(
        ["CVE-2021-44228", "CVE-2021-45046"],
        "log4j",
        store=memory_index_store,
        plan=plan,
    )
    found = {f["cve_id"] for f in result["prioritized"]}
    assert found == {"CVE-2021-44228", "CVE-2021-45046"}


def test_match_plan_full_returns_exact_confidence(memory_index_store):
    plan, conf = match_plan_full("log4j 2.14.0", store=memory_index_store)
    assert "CVE-2021-44228" in plan
    assert conf.get("CVE-2021-44228") == "exact"


def test_prioritized_entry_has_match_confidence(memory_index_store):
    result = prioritize_cves(["CVE-2021-44228"], "log4j 2.14.0", store=memory_index_store)
    entry = result["prioritized"][0]
    assert entry["match_confidence"] == "exact"


def test_prioritize_reporting_semantics(memory_index_store):
    result = prioritize_cves(
        ["CVE-2021-44228", "CVE-9999-0000"],
        "log4j 2.14.0",
        store=memory_index_store,
    )
    assert result["actionable"] == 1
    assert result["found"] == 1
    assert result["not_applicable"] == 1  # CVE-9999-0000 -> not_found
    assert result["risk_suppressed"] == 0
    assert result["false_positive_rate"] == result["not_applicable_rate"]
    assert result["reduction_rate"] == 50.0
