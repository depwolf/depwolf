"""Accuracy-hardening regression tests (v0.1.6.1).

Validates the hardened contract:
  - canonical version data propagates scan -> finding -> remediation unchanged;
  - applicability is tri-state (YES/NO/UNKNOWN) against authoritative ranges;
  - UNKNOWN versions are never actionable and surface as verification required;
  - non-applicable findings produce no remediation commands;
  - remediation never recommends a downgrade;
  - range boundaries (including/excluding) are honored.
"""

import sqlite3

from depwolf.application.matcher import prioritize_cves
from depwolf.application.remediation import _safe_upgrade_target, generate_remediation, verify_fix
from depwolf.infrastructure.cpe_index import _ensure_schema
from depwolf.infrastructure.store import SqliteIndexStore

_INSERT = """INSERT INTO cpe_index
    (vendor, product, version_start_including, version_start_excluding,
     version_end_including, version_end_excluding, cve_id, description,
     cvss_score, cvss_severity, epss_score, kev, published_date)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""

JQUERY_DESC = (
    "jQuery before 3.5.0 does not neutralize untrusted HTML passed to the DOM in certain contexts (CVE-2020-11023 XSS)."
)


def _jquery_store(tmp_path, dual=False):
    path = tmp_path / "jquery.db"
    db = sqlite3.connect(str(path))
    _ensure_schema(db)
    db.execute(
        _INSERT,
        (
            "jquery",
            "jquery",
            None,
            None,
            None,
            "3.5.0",
            "CVE-2020-11023",
            JQUERY_DESC,
            9.0,
            "CRITICAL",
            0.9,
            1,
            "2020-04-29T00:00:00.000",
        ),
    )
    if dual:
        # A second, unbounded configuration for the same CVE (mirrors real NVD
        # data with overlapping CPE configs). Kept only for the downgrade-guard
        # test: the unbounded row makes 4.0.0 in-scope while the DB's fixed
        # version (3.5.0) is older than the installed version.
        db.execute(
            _INSERT,
            (
                "jquery",
                "jquery",
                None,
                None,
                None,
                None,
                "CVE-2020-11023",
                JQUERY_DESC,
                9.0,
                "CRITICAL",
                0.9,
                1,
                "2020-04-29T00:00:00.000",
            ),
        )
    db.commit()
    db.close()
    return SqliteIndexStore(path)


def _range_store(tmp_path, start_incl, start_excl, end_incl, end_excl):
    path = tmp_path / "ranges.db"
    db = sqlite3.connect(str(path))
    _ensure_schema(db)
    db.execute(
        _INSERT,
        (
            "apache",
            "log4j",
            start_incl,
            start_excl,
            end_incl,
            end_excl,
            "CVE-2021-44228",
            "Apache Log4j2 JNDI injection",
            10.0,
            "CRITICAL",
            0.9757,
            1,
            "2021-12-10T10:00:00.000",
        ),
    )
    db.commit()
    db.close()
    return SqliteIndexStore(path)


def _npm_jquery_dep():
    return {
        "jquery": {
            "name": "jquery",
            "version": "2.2.0",
            "ecosystem": "npm",
            "artifact": "jquery",
            "manifest": "package.json",
            "direct": True,
            "path": [],
            "version_confidence": "EXACT",
            "version_source": "manifest",
        }
    }


def test_scan_knows_exact_version_and_marks_yes(tmp_path):
    store = _jquery_store(tmp_path)
    result = prioritize_cves(["CVE-2020-11023"], "jquery 2.2.0", store=store, deps_index=_npm_jquery_dep())
    assert result["found"] == 1
    e = result["prioritized"][0]
    assert e["applicable"] == "YES"
    assert e["package"] == "jquery"
    assert e["ecosystem"] == "npm"
    assert e["version_confidence"] == "EXACT"
    assert e["version_source"] == "manifest"


def test_in_range_is_yes(memory_index_store):
    result = prioritize_cves(["CVE-2021-44228"], "log4j 2.14.1", store=memory_index_store)
    assert result["found"] == 1
    assert result["prioritized"][0]["applicable"] == "YES"


def test_out_of_range_is_filtered_no(tmp_path):
    # 4.0.0 is above CVE-2020-11023's affected range (< 3.5.0): the scan must
    # filter it out (NOT APPLICABLE), not keep it as an actionable finding.
    store = _jquery_store(tmp_path)
    result = prioritize_cves(["CVE-2020-11023"], "jquery 4.0.0", store=store)
    assert result["found"] == 0
    reasons = {f["cve_id"]: f["reason"] for f in result["filtered_details"]}
    assert reasons["CVE-2020-11023"] == "not_in_stack"
    assert result["needs_verification"] == 0


def test_unknown_version_not_actionable(memory_index_store):
    # Stack line without a version: the product is present but the installed
    # version is unknown -> verification required, never a confirmed finding.
    result = prioritize_cves(["CVE-2021-44228"], "log4j", store=memory_index_store)
    assert result["found"] == 0
    assert result["needs_verification"] == 1
    reasons = {f["cve_id"]: f["reason"] for f in result["filtered_details"]}
    assert reasons["CVE-2021-44228"] == "unresolved_version"
    assert "verification required" in result["filtered_details"][0]["detail"].lower()


def test_scan_remediation_propagation(tmp_path, monkeypatch):
    # The scan resolves jquery 2.2.0 EXACT; the same remediation that runs
    # against that finding must see the identical version, not UNKNOWN.
    store = _jquery_store(tmp_path)
    monkeypatch.setattr("depwolf.infrastructure.store.DB_PATH", store.path)
    from depwolf.interfaces.cli import _attach_remediation

    result = prioritize_cves(["CVE-2020-11023"], "jquery 2.2.0", store=store, deps_index=_npm_jquery_dep())
    _attach_remediation(result["prioritized"], _npm_jquery_dep())
    rem = result["prioritized"][0]
    assert rem["installed_version"] == "2.2.0"
    assert rem["version_confidence"] == "EXACT"
    assert rem["version_source"] == "manifest"
    assert rem["applicable"] == "YES"
    assert rem["dependency_type"] == "DIRECT"
    assert any("npm install jquery@3.5.0" in c for c in rem["patch_commands"])


def test_non_applicable_emits_no_commands(tmp_path):
    store = _jquery_store(tmp_path)
    rem = generate_remediation(
        "CVE-2020-11023",
        store=store,
        context={"installed_version": "4.0.0", "ecosystem": "npm", "artifact": "jquery", "direct": True},
    )
    assert rem["applicable"] == "NO"
    assert rem["patch_commands"] == []
    assert rem["file_change"] is None
    assert "NOT APPLICABLE" in rem["recommended_action"]


def test_unknown_version_verification_not_actionable(tmp_path):
    store = _jquery_store(tmp_path)
    rem = generate_remediation(
        "CVE-2020-11023",
        store=store,
        context={"ecosystem": "npm", "artifact": "jquery"},
    )
    assert rem["applicable"] == "UNKNOWN"
    assert rem["version_confidence"] == "UNKNOWN"
    assert "VERIFICATION REQUIRED" in rem["recommended_action"]
    assert any("npm ls jquery" in c for c in rem["patch_commands"])
    assert not any("npm install" in c for c in rem["patch_commands"])
    assert rem["file_change"] is None


def test_no_unsafe_downgrade_target():
    assert _safe_upgrade_target("4.0.0", "3.5.0") is None
    assert _safe_upgrade_target("2.2.0", "3.5.0") == "3.5.0"
    assert _safe_upgrade_target(None, "3.5.0") == "3.5.0"


def test_remediation_never_downgrades_affected_newer_than_fixed(tmp_path):
    # Dual-config store: installed 4.0.0 is in-scope via the unbounded row, but
    # the DB fixed version (3.5.0) is older than what is installed. The engine
    # must NOT recommend npm install jquery@3.5.0 (a silent downgrade).
    store = _jquery_store(tmp_path, dual=True)
    rem = generate_remediation(
        "CVE-2020-11023",
        store=store,
        context={"installed_version": "4.0.0", "ecosystem": "npm", "artifact": "jquery", "direct": True},
    )
    assert rem["applicable"] == "YES"
    assert rem["fixed_version"] == "3.5.0"
    assert not any("npm install jquery@3.5.0" in c for c in rem["patch_commands"])
    assert "no safe upgrade target" in rem["recommended_action"].lower()


def test_range_boundary_include_exclude(memory_index_store):
    # CVE-2021-44228 affected range: 2.0 <= v < 2.15.0
    assert verify_fix("CVE-2021-44228", "2.0", store=memory_index_store) == "still_vulnerable"
    assert verify_fix("CVE-2021-44228", "2.0.0", store=memory_index_store) == "still_vulnerable"
    assert verify_fix("CVE-2021-44228", "2.14.9", store=memory_index_store) == "still_vulnerable"
    assert verify_fix("CVE-2021-44228", "1.9.9", store=memory_index_store) == "fixed"
    assert verify_fix("CVE-2021-44228", "2.15.0", store=memory_index_store) == "fixed"


def test_range_boundary_start_excluding_end_including(tmp_path):
    # Affected: 1.0.0 < v <= 2.5.0
    store = _range_store(tmp_path, None, "1.0.0", "2.5.0", None)
    assert verify_fix("CVE-2021-44228", "1.0.0", store=store) == "fixed"  # start excluded
    assert verify_fix("CVE-2021-44228", "1.0.1", store=store) == "still_vulnerable"
    assert verify_fix("CVE-2021-44228", "2.5.0", store=store) == "still_vulnerable"  # end included
    assert verify_fix("CVE-2021-44228", "2.5.1", store=store) == "fixed"
