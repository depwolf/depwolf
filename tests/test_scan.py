from depwolf.matcher import prioritize_cves
from depwolf.remediation import generate_remediation


def test_funnel_reduces_raw_candidates(index_store):
    result = prioritize_cves(
        ["CVE-2021-44228", "CVE-2021-45046", "CVE-9999-0000"],
        "log4j 2.14.1",
        store=index_store,
    )
    assert result["found"] >= 1
    assert result["filtered_out"] > 0
    assert result["false_positive_rate"] > 0
    assert "CVE-9999-0000" not in {f["cve_id"] for f in result["prioritized"]}
    reasons = {d["reason"] for d in result["filtered_details"]}
    assert "not_found" in reasons


def test_log4shell_present_and_fix_now(index_store):
    result = prioritize_cves(["CVE-2021-44228"], "log4j 2.14.1", store=index_store)
    ids = {f["cve_id"] for f in result["prioritized"]}
    assert "CVE-2021-44228" in ids
    entry = next(f for f in result["prioritized"] if f["cve_id"] == "CVE-2021-44228")
    assert entry["risk_score"] >= 80
    assert entry["patch_priority"] == "Immediate"


def test_out_of_range_version_filtered(index_store):
    result = prioritize_cves(["CVE-2021-44228"], "log4j 2.17.1", store=index_store)
    assert "CVE-2021-44228" not in {f["cve_id"] for f in result["prioritized"]}
    reasons = {d["reason"] for d in result["filtered_details"]}
    assert "not_in_stack" in reasons


def test_fake_cve_filtered_not_found(index_store):
    result = prioritize_cves(["CVE-9999-0000"], "log4j 2.14.1", store=index_store)
    assert result["found"] == 0
    reasons = {d["reason"] for d in result["filtered_details"]}
    assert "not_found" in reasons


def test_remediation_db_grounded_log4shell(index_store):
    rem = generate_remediation("CVE-2021-44228", store=index_store)
    assert rem["found"] is True
    assert rem["fixed_version"] == "2.15.0"
    assert rem["patch_commands"], "expected patch commands"
    assert rem["step_by_step_fix"], "expected step-by-step plan"
    assert "log4j" in (rem["executive_summary"] or "").lower()


def test_ignored_cve_filtered(memory_index_store):
    from depwolf.matcher import ignore_cve

    ignore_cve("CVE-2021-44228", store=memory_index_store)
    result = prioritize_cves(["CVE-2021-44228"], "log4j 2.14.1", store=memory_index_store)
    assert "CVE-2021-44228" not in {f["cve_id"] for f in result["prioritized"]}
    reasons = {d["reason"] for d in result["filtered_details"]}
    assert "ignored" in reasons
