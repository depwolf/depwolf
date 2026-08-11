"""Phase 6 tests: typed scanner adapters emit canonical CVEReference objects."""

from depwolf.application.ingest import extract_cves, extract_findings
from depwolf.domain.model import CVEReference

TRIVY = {
    "Results": [
        {
            "Target": "app",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2021-44228",
                    "PkgName": "log4j-core",
                    "InstalledVersion": "2.14.1",
                    "FixedVersion": "2.15.0",
                    "Severity": "CRITICAL",
                }
            ],
        }
    ],
}

GRYPE = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2021-44228",
                "severity": "Critical",
                "fix": {"versions": ["2.15.0"]},
            },
            "artifact": {"name": "log4j-core", "version": "2.14.1"},
        }
    ],
}

SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "CodeQL"}},
            "results": [
                {
                    "ruleId": "CVE-2021-44228",
                    "message": {"text": "Log4Shell"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "pom.xml"}}}],
                }
            ],
        }
    ],
}


def _single(refs):
    assert isinstance(refs, list) and refs, "expected at least one ref"
    assert all(isinstance(r, CVEReference) for r in refs)
    return refs[0]


def test_trivy_adapter_typed():
    ref = _single(extract_cves(TRIVY))
    assert ref.cve_id == "CVE-2021-44228"
    assert ref.source == "trivy"
    assert ref.installed_version == "2.14.1"
    assert ref.fixed_version == "2.15.0"
    assert ref.confidence == 1.0


def test_grype_adapter_typed():
    ref = _single(extract_cves(GRYPE))
    assert ref.cve_id == "CVE-2021-44228"
    assert ref.source == "grype"
    assert ref.pkg == "log4j-core"
    assert ref.fixed_version == "2.15.0"


def test_sarif_adapter_typed():
    ref = _single(extract_cves(SARIF))
    assert ref.cve_id == "CVE-2021-44228"
    assert ref.source == "codeql"
    assert ref.target == "pom.xml"


def test_heuristic_fallback_low_confidence():
    ref = _single(extract_cves({"unknown_schema": {"list": ["CVE-2021-44228"]}}))
    assert ref.cve_id == "CVE-2021-44228"
    assert ref.confidence == 0.3


def test_text_extraction():
    ref = _single(extract_cves("log4j-core 2.14.1 CVE-2021-44228\n"))
    assert ref.cve_id == "CVE-2021-44228"
    assert ref.pkg == "log4j-core"
    assert ref.installed_version == "2.14.1"


def test_extract_findings_dict_shape():
    out = extract_findings(TRIVY)
    assert out[0]["cve_id"] == "CVE-2021-44228"
    assert out[0]["source"] == "trivy"
    assert out[0]["confidence"] == 1.0
