"""Phase 6 tests: canonical model serialization round-trips."""

import dataclasses

from depwolf.domain.model import CVEReference, Finding


def test_cve_reference_roundtrip():
    r = CVEReference(
        cve_id="cve-2021-44228",
        pkg="log4j-core",
        installed_version="2.14.1",
        fixed_version="2.15.0",
        severity="CRITICAL",
        target="app",
        source="trivy",
        confidence=1.0,
    )
    again = CVEReference.from_dict(r.to_dict())
    assert again.cve_id == "CVE-2021-44228"
    assert again.source == "trivy"
    assert again.confidence == 1.0
    assert again == dataclasses.replace(r, cve_id="CVE-2021-44228")


def test_finding_entry_uses_canonical_keys():
    ref = CVEReference(cve_id="CVE-2021-44228", pkg="log4j-core")
    finding = Finding(cve=ref)
    entry = finding.to_entry_dict()
    assert entry["cve_id"] == "CVE-2021-44228"
    assert entry["pkg"] == "log4j-core"
    assert "severity" not in entry  # no risk yet -> absent, not guessed
    assert "fixed_version" not in entry or entry["fixed_version"] is None


def test_finding_with_verdict_exposes_patch_priority():
    from depwolf.domain.model import PolicyVerdict

    finding = Finding(
        cve=CVEReference(cve_id="CVE-2021-44228"),
        verdict=PolicyVerdict(decision="allow", reason="ok", patch_priority="Immediate", sla_hours=4),
    )
    entry = finding.to_entry_dict()
    assert entry["patch_priority"] == "Immediate"
    assert entry["patch_sla_hours"] == 4
    assert entry["verdict"] == "allow"
