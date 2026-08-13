"""Regression tests: installed-version propagation + version-range applicability gate.

Mirrors the WebGoat false positive: jquery 4.0.0 installed, CVE-2020-11023
affected range >= 1.0.3 and < 3.5.0. Only YES may become an actionable finding;
NO must be filtered out as not applicable; UNKNOWN must never be treated as a
confirmed vulnerability; and the scan-resolved version must be the same version
remediation receives.
"""

import json
import sqlite3

import pytest

from depwolf.application.filters import NotInStackFilter
from depwolf.application.matcher import prioritize_cves
from depwolf.application.remediation import generate_remediation
from depwolf.domain.funnel import FilterContext
from depwolf.domain.model import Asset
from depwolf.domain.versions import version_applicability
from depwolf.infrastructure.cpe_index import _ensure_schema
from depwolf.infrastructure.store import SqliteIndexStore
from depwolf.interfaces.cli import _attach_remediation, _remediation_context

JQUERY_ROWS = [
    (
        "jquery",
        "jquery",
        "1.0.3",
        None,
        None,
        "3.5.0",
        "CVE-2020-11023",
        "jQuery before 3.5.0 mishandles jQuery.htmlPrefilter (XSS)",
        9.8,
        "CRITICAL",
        0.9,
        0,
        "2020-04-29T00:00:00.000",
    ),
    (
        "jquery",
        "jquery",
        "1.0.3",
        None,
        None,
        "3.5.0",
        "CVE-2020-11022",
        "jQuery before 3.5.0 has an XSS in jQuery.htmlPrefilter",
        6.1,
        "MEDIUM",
        0.6,
        0,
        "2020-04-29T00:00:00.000",
    ),
]

_COLS = (
    "vendor, product, version_start_including, version_start_excluding, "
    "version_end_including, version_end_excluding, cve_id, description, "
    "cvss_score, cvss_severity, epss_score, kev, published_date"
)


@pytest.fixture
def jquery_store(tmp_path):
    path = tmp_path / "cpe_index.db"
    db = sqlite3.connect(str(path))
    _ensure_schema(db)
    db.executemany(f"INSERT INTO cpe_index ({_COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", JQUERY_ROWS)
    db.commit()
    db.close()
    return SqliteIndexStore(path)


def _ctx(store, cve_id, assets):
    return FilterContext(
        cve_id=cve_id,
        rows=store.cve(cve_id),
        assets=[Asset(a["product"], a["version"]) for a in assets],
        os_filter=None,
        ignored=set(),
    )


def _write_lock(root, version):
    (root / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "webgoat",
                "lockfileVersion": 3,
                "packages": {"": {}, "node_modules/jquery": {"version": version}},
            }
        ),
        encoding="utf-8",
    )


def _dep_index(collected):
    index = {}
    for d in collected["deps"]:
        index[d["name"]] = d
        if d.get("artifact"):
            index.setdefault(d["artifact"], d)
    return index


# 1. Known affected version -> YES -> actionable.


def test_known_affected_version_is_yes(jquery_store):
    ctx = _ctx(jquery_store, "CVE-2020-11023", [{"product": "jquery", "version": "3.4.1"}])
    NotInStackFilter().apply(ctx)
    assert ctx.reason is None
    assert ctx.affected_assets == ["jquery"]
    assert ctx.matched_row is not None

    result = prioritize_cves(["CVE-2020-11023"], "jquery 3.4.1", store=jquery_store)
    entry = next(f for f in result["prioritized"] if f["cve_id"] == "CVE-2020-11023")
    assert entry["installed_version"] == "3.4.1"


# 2. Known non-affected version -> NO -> filtered out, never actionable.


def test_known_non_affected_version_is_no(jquery_store):
    result = prioritize_cves(["CVE-2020-11023"], "jquery 4.0.0", store=jquery_store)
    assert "CVE-2020-11023" not in {f["cve_id"] for f in result["prioritized"]}
    assert result["actionable"] == 0
    details = [d for d in result["filtered_details"] if d["reason"] == "not_in_stack"]
    assert details, "expected the CVE to be filtered as not applicable"
    assert any("outside the vulnerable range" in d.get("detail", "") for d in details)


# 3. Unknown version -> UNKNOWN -> never actionable, never '- + exact'.


def test_unknown_version_is_unknown(jquery_store):
    result = prioritize_cves(["CVE-2020-11023"], "jquery", store=jquery_store)
    assert "CVE-2020-11023" not in {f["cve_id"] for f in result["prioritized"]}
    assert result["actionable"] == 0
    details = [d for d in result["filtered_details"] if d["reason"] == "not_in_stack"]
    assert any("could not be determined" in d.get("detail", "") for d in details)
    for f in result["prioritized"]:
        if f.get("match_confidence") == "exact":
            assert f.get("installed_version"), "exact-confidence finding must carry a resolved version"


# 4. jquery 4.0.0 + CVE-2020-11023 (the reported WebGoat false positive).


def test_webgoat_jquery_4_0_0_false_positive(jquery_store, tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "webgoat", "dependencies": {"jquery": "^4.0.0"}}), encoding="utf-8"
    )
    _write_lock(tmp_path, "4.0.0")

    from depwolf.application.scanner import scan_project

    result = scan_project(tmp_path, store=jquery_store)
    ids = {f["cve_id"] for f in result["prioritized"]}
    assert "CVE-2020-11023" not in ids
    assert "CVE-2020-11022" not in ids


def test_webgoat_jquery_affected_version_is_actionable(jquery_store, tmp_path):
    _write_lock(tmp_path, "3.4.1")

    from depwolf.application.scanner import scan_project

    result = scan_project(tmp_path, store=jquery_store)
    entry = next(f for f in result["prioritized"] if f["cve_id"] == "CVE-2020-11023")
    assert entry["installed_version"] == "3.4.1"


# 5. Scan and remediation receive the identical installed version.


def test_scan_and_remediation_share_installed_version(jquery_store, tmp_path, monkeypatch):
    import depwolf.infrastructure.store as store_mod

    monkeypatch.setattr(store_mod, "DB_PATH", jquery_store.path)
    _write_lock(tmp_path, "3.4.1")

    from depwolf.application.scanner import collect_project, scan_project

    result = scan_project(tmp_path, store=jquery_store)
    entry = next(f for f in result["prioritized"] if f["cve_id"] == "CVE-2020-11023")
    assert entry["installed_version"] == "3.4.1"

    collected = collect_project(tmp_path, store=jquery_store)
    dep_index = _dep_index(collected)
    ctx = _remediation_context(dep_index, entry)
    assert ctx is not None
    assert ctx["installed_version"] == "3.4.1"

    rem = generate_remediation("CVE-2020-11023", store=jquery_store, context=ctx)
    assert rem["installed_version"] == "3.4.1"
    assert rem["applicable"] is True

    _attach_remediation([entry], dep_index)
    assert entry["installed_version"] == "3.4.1"
    assert entry.get("remediation_summary")


def test_remediation_context_does_not_fall_back_to_unknown():
    dep_index = {"jquery": {"name": "jquery", "version": None, "ecosystem": "npm", "artifact": "jquery"}}
    ctx = _remediation_context(dep_index, {"affected_assets": ["jquery"], "installed_version": "3.4.1", "pkg": None})
    assert ctx is not None
    assert ctx["installed_version"] == "3.4.1"


# 6/7. NO and UNKNOWN findings never enter the actionable set (covered by the
# funnel assertions above; explicit counts here).


def test_no_and_unknown_findings_never_actionable(jquery_store):
    no = prioritize_cves(["CVE-2020-11023"], "jquery 4.0.0", store=jquery_store)
    unknown = prioritize_cves(["CVE-2020-11023"], "jquery", store=jquery_store)
    assert no["actionable"] == 0 and no["found"] == 0
    assert unknown["actionable"] == 0 and unknown["found"] == 0


# 8. Inclusive/exclusive version-range boundaries (shared tri-state engine).


def test_version_applicability_boundaries():
    r = [("2.0", None, None, "2.15.0")]  # >= 2.0 and < 2.15.0
    assert version_applicability("2.0", r) is True
    assert version_applicability("2.14.9", r) is True
    assert version_applicability("2.15.0", r) is False
    assert version_applicability("1.9", r) is False

    r = [(None, "2.0", None, None)]  # > 2.0
    assert version_applicability("2.0", r) is False
    assert version_applicability("2.0.1", r) is True

    r = [("2.0", None, "2.15.0", None)]  # >= 2.0 and <= 2.15.0
    assert version_applicability("2.15.0", r) is True
    assert version_applicability("2.15.1", r) is False

    # a range with no bounds means "all versions affected"
    assert version_applicability("4.0.0", [(None, None, None, None)]) is True

    # unknown version -> UNKNOWN regardless of the range
    assert version_applicability(None, [("2.0", None, None, "2.15.0")]) is None
    assert version_applicability("1.0", []) is None


# Stack hygiene: a versionless duplicate must not shadow a resolved version.


def test_versionless_duplicate_does_not_shadow_resolved_version(jquery_store):
    result = prioritize_cves(["CVE-2020-11023"], "jquery 4.0.0\njquery", store=jquery_store)
    assert "CVE-2020-11023" not in {f["cve_id"] for f in result["prioritized"]}

    result_ok = prioritize_cves(["CVE-2020-11023"], "jquery 3.4.1\njquery", store=jquery_store)
    entry = next(f for f in result_ok["prioritized"] if f["cve_id"] == "CVE-2020-11023")
    assert entry["installed_version"] == "3.4.1"


# --- Version flow for real-world package names (Maven / scoped npm / Go) ---
#
# trivy and the pom parser emit Maven deps as "group:artifact version". If the
# stack parser cannot split them, the installed version is lost and the asset
# degrades to UNKNOWN, so a WebGoat-style Java report would drop every finding.


def test_parse_stack_extracts_java_scoped_go_versions():
    from depwolf.application.matcher import parse_stack

    assert parse_stack("org.apache.logging.log4j:log4j-core 2.14.0") == [
        {"product": "org.apache.logging.log4j:log4j-core", "version": "2.14.0"}
    ]
    assert parse_stack("@babel/core 7.24.0") == [{"product": "@babel/core", "version": "7.24.0"}]
    assert parse_stack("github.com/gin-gonic/gin v1.9.0") == [
        {"product": "github.com/gin-gonic/gin", "version": "v1.9.0"}
    ]
    assert parse_stack("jquery 4.0.0") == [{"product": "jquery", "version": "4.0.0"}]


def test_assets_reduce_maven_coordinates_keeping_version():
    from depwolf.application.matcher import _assets

    assets = _assets("org.apache.logging.log4j:log4j-core 2.14.0")
    assert [(a.product, a.version) for a in assets] == [("log4j-core", "2.14.0")]


def test_findings_stack_keeps_java_version():
    from depwolf.application.ingest import findings_stack
    from depwolf.domain.model import CVEReference

    refs = [
        CVEReference(
            cve_id="CVE-2021-44228",
            pkg="org.apache.logging.log4j:log4j-core",
            installed_version="2.14.0",
            source="trivy",
        )
    ]
    assert findings_stack(refs) == "org.apache.logging.log4j:log4j-core 2.14.0"


def test_trivy_java_finding_flows_version_into_funnel():
    from depwolf.application.adapters import TrivyAdapter

    report = {
        "Results": [
            {
                "Target": "pom.xml",
                "Class": "lang-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-44228",
                        "PkgName": "org.apache.logging.log4j:log4j-core",
                        "InstalledVersion": "2.14.0",
                        "Severity": "CRITICAL",
                    }
                ],
            }
        ]
    }
    refs = TrivyAdapter().extract(report)
    from depwolf.application.ingest import findings_stack

    assert findings_stack(refs) == "org.apache.logging.log4j:log4j-core 2.14.0"

    result = prioritize_cves(
        [r.cve_id for r in refs],
        findings_stack(refs),
        store=LOG4J_STORE(),
    )
    entry = next(f for f in result["prioritized"] if f["cve_id"] == "CVE-2021-44228")
    assert entry["installed_version"] == "2.14.0"
    assert entry["match_confidence"] == "exact"


def _log4j_store():
    store = SqliteIndexStore(memory=True)
    # CVE-2021-44228: >= 2.0-beta9 and < 2.15.0, or >= 2.16.0 and < 2.17.1.
    rows = [
        (
            "apache",
            "log4j-core",
            "2.0-beta9",
            None,
            None,
            "2.15.0",
            "CVE-2021-44228",
            "Apache Log4j2 2.0-beta9 through 2.15.0 remote code execution",
            10.0,
            "CRITICAL",
            0.97,
            1,
            "2021-12-10T00:00:00.000",
        ),
        (
            "apache",
            "log4j-core",
            "2.16.0",
            None,
            None,
            "2.17.1",
            "CVE-2021-44228",
            "Apache Log4j2 2.16.0 through 2.16.1 remote code execution",
            10.0,
            "CRITICAL",
            0.97,
            1,
            "2021-12-10T00:00:00.000",
        ),
    ]
    conn = store.open()
    conn.executemany(
        f"INSERT INTO cpe_index ({_COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    store.close(conn)
    return store


LOG4J_STORE = _log4j_store


def test_java_version_range_gate_yes_and_no():
    store = LOG4J_STORE()

    yes = prioritize_cves(["CVE-2021-44228"], "org.apache.logging.log4j:log4j-core 2.14.0", store=store)
    entry = next(f for f in yes["prioritized"] if f["cve_id"] == "CVE-2021-44228")
    assert entry["installed_version"] == "2.14.0"

    no = prioritize_cves(["CVE-2021-44228"], "org.apache.logging.log4j:log4j-core 2.17.1", store=store)
    assert "CVE-2021-44228" not in {f["cve_id"] for f in no["prioritized"]}
    assert any(d["reason"] == "not_in_stack" for d in no["filtered_details"])

    yes2 = prioritize_cves(["CVE-2021-44228"], "org.apache.logging.log4j:log4j-core 2.16.0", store=store)
    assert "CVE-2021-44228" in {f["cve_id"] for f in yes2["prioritized"]}
