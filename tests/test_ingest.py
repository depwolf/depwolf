import json
from pathlib import Path

from depwolf.ingest import dedupe, extract_findings, findings_stack

EX = Path(__file__).resolve().parent.parent / "examples"


def _load(name):
    return json.loads((EX / name).read_text(encoding="utf-8"))


def test_trivy_json_extraction():
    findings = extract_findings(_load("trivy.json"))
    ids = {f["cve_id"] for f in findings}
    assert "CVE-2021-44228" in ids
    assert "CVE-2021-45046" in ids
    assert "CVE-9999-0000" in ids
    log4shell = next(f for f in findings if f["cve_id"] == "CVE-2021-44228")
    assert log4shell["pkg"] == "log4j"
    assert log4shell["installed_version"] == "2.14.1"
    assert log4shell["fixed_version"] == "2.15.0"
    assert log4shell["target"] == "app/requirements.txt"


def test_trivy_dedupe_and_stack():
    findings = dedupe(extract_findings(_load("trivy.json")))
    assert len(findings) == 3
    stack = findings_stack(findings)
    assert "log4j 2.14.1" in stack


def test_grype_artifact_context():
    findings = extract_findings(_load("grype.json"))
    by_id = {f["cve_id"]: f for f in findings}
    assert by_id["CVE-2021-44228"]["pkg"] == "log4j"
    assert by_id["CVE-2021-44228"]["installed_version"] == "2.14.1"
    assert by_id["CVE-2021-44228"]["severity"] == "Critical"
    assert by_id["CVE-9999-0000"]["pkg"] == "ghostpkg"


def test_sarif_ruleid_and_location():
    findings = extract_findings(_load("sast.sarif"))
    by_id = {f["cve_id"]: f for f in findings}
    assert "CVE-2021-44228" in by_id
    assert by_id["CVE-2021-44228"]["target"] == "src/main/java/App.java"


def test_plain_text():
    text = (EX / "scanner.txt").read_text(encoding="utf-8")
    findings = extract_findings(text)
    by_id = {f["cve_id"]: f for f in findings}
    assert by_id["CVE-2021-44228"]["pkg"] == "log4j"
    assert by_id["CVE-2021-44228"]["installed_version"] == "2.14.1"
    assert "CVE-2021-30517" in by_id


def test_no_cves_returns_empty():
    assert extract_findings({"Results": [{"Vulnerabilities": []}]}) == []
    assert extract_findings("nothing here\nstill nothing") == []
