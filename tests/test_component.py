"""Phase 1 component identity (spec §2/§13/§15/§16).

purl parsing, curated CPE hints for AI/alias packages, and the purl-driven
resolution that lets ``torch`` find NVD's ``pytorch`` rows when raw name
matching would miss them.
"""

from __future__ import annotations

import pytest

from depwolf.application.adapters import GrypeAdapter, TrivyAdapter
from depwolf.application.ingest import dedupe_cves, findings_stack
from depwolf.application.matcher import _resolution_names, match_plan_full_plus, prioritize_cves
from depwolf.domain.component import component_from_purl, parse_purl
from depwolf.domain.model import Asset, CVEReference

PYTORCH_ROW = (
    "pytorch",
    "pytorch",
    None,
    None,
    None,
    "2.3.1",
    "CVE-2026-12345",
    "PyTorch versions before 2.3.1 have a vulnerable model loading path",
    9.8,
    "CRITICAL",
    0.5,
    1,
    "2026-01-01T00:00:00.000",
)

UTIL_LINUX_ROW = (
    "util-linux",
    "util-linux",
    None,
    None,
    None,
    "2.39.15",
    "CVE-2026-76642",
    "libmount/exec utilities mishandle crafted mtab input",
    9.8,
    "CRITICAL",
    0.001,
    0,
    "2026-01-01T00:00:00.000",
)


def _seed_row(conn, row) -> None:
    conn.execute(
        """INSERT INTO cpe_index
           (vendor, product, version_start_including, version_start_excluding,
            version_end_including, version_end_excluding, cve_id, description,
            cvss_score, cvss_severity, epss_score, kev, published_date)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        row,
    )
    conn.commit()


# ---- purl parsing ---------------------------------------------------------


def test_parse_purl_variants():
    p = parse_purl("pkg:pypi/torch@2.2.0")
    assert p is not None
    assert p.type == "pypi"
    assert p.name == "torch"
    assert p.version == "2.2.0"
    assert p.namespace is None


def test_parse_purl_with_namespace_and_qualifiers():
    p = parse_purl("pkg:deb/debian/libssl1.1?arch=amd64")
    assert p is not None
    assert p.type == "deb"
    assert p.namespace == "debian"
    assert p.name == "libssl1.1"
    assert p.qualifiers == {"arch": "amd64"}


def test_parse_purl_subpath_and_versionless():
    assert parse_purl("pkg:npm/@scope/pkg@1.0.0#sub").name == "pkg"
    p = parse_purl("pkg:gem/rails")
    assert p is not None and p.version is None


def test_parse_purl_invalid():
    assert parse_purl(None) is None
    assert parse_purl("") is None
    assert parse_purl("not-a-purl") is None
    assert parse_purl("deb/debian/foo") is None


# ---- component + CPE hints ------------------------------------------------


@pytest.mark.parametrize(
    "purl,vendor,product",
    [
        ("pkg:pypi/torch@2.2.0", "pytorch", "pytorch"),
        ("pkg:pypi/torchvision@0.17.0", "pytorch", "torchvision"),
        ("pkg:pypi/tensorflow-cpu@2.10.0", "google", "tensorflow"),
        ("pkg:pypi/tensorflow-gpu@2.10.0", "google", "tensorflow"),
        ("pkg:pypi/onnxruntime@1.14.0", "microsoft", "onnxruntime"),
        ("pkg:pypi/transformers@4.30.0", "huggingface", "transformers"),
        ("pkg:pypi/scikit-learn@1.3.0", "scikit-learn", "scikit-learn"),
        ("pkg:pypi/requests@2.28.0", None, None),  # no curated hint
        # Debian binary -> upstream CPE library alias
        ("pkg:deb/debian/libmount1@2.39.10", "util-linux", "util-linux"),
        ("pkg:deb/debian/bsdutils@2.39.10", "util-linux", "util-linux"),
        ("pkg:deb/debian/libsystemd0@256.4", "freedesktop", "systemd"),
        ("pkg:deb/debian/libudev1@256.4", "freedesktop", "systemd"),
        ("pkg:deb/debian/libacl1@2.3.1", "acl", "acl"),
        ("pkg:deb/debian/libncursesw6@6.4", "invisible-island", "ncurses"),
        ("pkg:deb/debian/perl-base@5.38.2", "archive", "perl"),
        ("pkg:deb/debian/bash@5.2.21", None, None),  # no curated hint
    ],
)
def test_component_hints(purl, vendor, product):
    c = component_from_purl(purl)
    assert c is not None
    assert c.ecosystem == purl.split(":")[1].split("/")[0]
    assert c.vendor == vendor
    assert c.product == product


def test_resolution_names_appends_hint():
    a = Asset(product="torch", version="2.2.0", purl="pkg:pypi/torch@2.2.0")
    assert _resolution_names(a) == ["torch", "pytorch"]


def test_resolution_names_no_hint_when_same():
    a = Asset(product="pytorch", version="2.2.0", purl="pkg:pypi/torch@2.2.0")
    assert _resolution_names(a) == ["pytorch"]


def test_resolution_names_ignores_unknown_purl():
    a = Asset(product="requests", version="2.28.0", purl="pkg:pypi/requests@2.28.0")
    assert _resolution_names(a) == ["requests"]


# ---- purl flow from findings to stack -------------------------------------


def test_findings_stack_includes_purl():
    refs = [
        CVEReference(
            cve_id="CVE-2026-12345",
            pkg="torch",
            installed_version="2.2.0",
            purl="pkg:pypi/torch@2.2.0",
            ecosystem="pypi",
        )
    ]
    stack = findings_stack(refs)
    assert "purl pkg:pypi/torch@2.2.0" in stack
    assert "torch 2.2.0" in stack


def test_ceref_round_trip_purl():
    r = CVEReference(cve_id="CVE-2026-12345", pkg="torch", purl="pkg:pypi/torch@2.2.0", ecosystem="pypi")
    d = r.to_dict()
    assert d["purl"] == "pkg:pypi/torch@2.2.0"
    assert d["ecosystem"] == "pypi"
    back = CVEReference.from_dict(d)
    assert back.purl == "pkg:pypi/torch@2.2.0"
    assert back.ecosystem == "pypi"


def test_dedupe_cves_merges_purl():
    a = CVEReference(cve_id="CVE-2026-12345", pkg="torch", source="trivy")
    b = CVEReference(cve_id="cve-2026-12345", pkg="torch", purl="pkg:pypi/torch@2.2.0")
    out = dedupe_cves([a, b])
    assert len(out) == 1
    assert out[0].purl == "pkg:pypi/torch@2.2.0"


# ---- adapters emit purl ---------------------------------------------------


def test_trivy_adapter_purl():
    data = {
        "Results": [
            {
                "Target": "app",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-12345",
                        "PkgName": "torch",
                        "InstalledVersion": "2.2.0",
                        "PkgIdentifier": {"PURL": "pkg:pypi/torch@2.2.0"},
                    }
                ],
            }
        ]
    }
    refs = TrivyAdapter().extract(data)
    assert refs[0].purl == "pkg:pypi/torch@2.2.0"


def test_grype_adapter_purl_and_type():
    data = {
        "source": {"target": "image"},
        "matches": [
            {
                "vulnerability": {"id": "CVE-2026-12345", "severity": "HIGH", "fix": {"versions": ["2.3.1"]}},
                "artifact": {"name": "torch", "version": "2.2.0", "type": "python", "purl": "pkg:pypi/torch@2.2.0"},
            }
        ],
    }
    refs = GrypeAdapter().extract(data)
    assert refs[0].purl == "pkg:pypi/torch@2.2.0"
    assert refs[0].ecosystem == "python"


# ---- purl-driven resolution against the index -----------------------------


def test_purl_aliases_product_in_plan(memory_index_store):
    _seed_row(memory_index_store.open(), PYTORCH_ROW)
    refs = [
        CVEReference(cve_id="CVE-2026-12345", pkg="torch", installed_version="2.2.0", purl="pkg:pypi/torch@2.2.0")
    ]
    plan, _, info = match_plan_full_plus(findings_stack(refs), store=memory_index_store)
    assert "CVE-2026-12345" in plan
    assert info["CVE-2026-12345"]["component"]["product"] == "pytorch"
    assert info["CVE-2026-12345"]["component"]["purl"] == "pkg:pypi/torch@2.2.0"
    assert any("via purl" in e for e in info["CVE-2026-12345"]["evidence"])


def test_prioritize_purl_resolution_entry(memory_index_store):
    _seed_row(memory_index_store.open(), PYTORCH_ROW)
    refs = [
        CVEReference(cve_id="CVE-2026-12345", pkg="torch", installed_version="2.2.0", purl="pkg:pypi/torch@2.2.0")
    ]
    result = prioritize_cves([r.cve_id for r in refs], findings_stack(refs), store=memory_index_store, refs=refs)
    assert result["found"] == 1
    entry = result["prioritized"][0]
    assert entry["cve_id"] == "CVE-2026-12345"
    assert entry["component"]["product"] == "pytorch"
    assert entry["component"]["purl"] == "pkg:pypi/torch@2.2.0"
    assert entry["component"]["ecosystem"] == "pypi"
    assert any("CPE alias 'pytorch'" in e for e in entry["evidence"])


def test_no_purl_no_alias_stays_filtered(memory_index_store):
    _seed_row(memory_index_store.open(), PYTORCH_ROW)
    result = prioritize_cves(["CVE-2026-12345"], "torch 2.2.0", store=memory_index_store)
    assert result["found"] == 0
    reasons = {d["reason"] for d in result["filtered_details"]}
    assert "not_in_stack" in reasons


# ---- Debian binary -> upstream CPE library alias ---------------------------


def test_deb_alias_resolves_in_funnel(memory_index_store):
    _seed_row(memory_index_store.open(), UTIL_LINUX_ROW)
    refs = [
        CVEReference(
            cve_id="CVE-2026-76642",
            pkg="libmount1",
            installed_version="2.39.10",
            purl="pkg:deb/debian/libmount1@2.39.10?distro=trixie",
        )
    ]
    result = prioritize_cves([r.cve_id for r in refs], findings_stack(refs), store=memory_index_store, refs=refs)
    assert result["found"] == 1
    entry = result["prioritized"][0]
    assert entry["component"]["product"] == "util-linux"
    assert entry["component"]["ecosystem"] == "deb"
    assert any("CPE alias 'util-linux'" in e for e in entry["evidence"])


def test_deb_alias_without_purl_stays_filtered(memory_index_store):
    _seed_row(memory_index_store.open(), UTIL_LINUX_ROW)
    result = prioritize_cves(["CVE-2026-76642"], "libmount1 2.39.10", store=memory_index_store)
    assert result["found"] == 0
    reasons = {d["reason"] for d in result["filtered_details"]}
    assert "not_in_stack" in reasons


def test_resolution_names_deb_alias():
    a = Asset(product="libmount1", version="2.39.10", purl="pkg:deb/debian/libmount1@2.39.10")
    assert _resolution_names(a) == ["libmount1", "util-linux"]